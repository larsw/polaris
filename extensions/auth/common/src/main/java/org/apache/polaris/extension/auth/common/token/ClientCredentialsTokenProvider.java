/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.polaris.extension.auth.common.token;

import static com.google.common.base.Preconditions.checkArgument;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Strings;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.entity.UrlEncodedFormEntity;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.NameValuePair;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.message.BasicNameValuePair;
import org.apache.polaris.nosql.async.AsyncExec;
import org.apache.polaris.nosql.async.Cancelable;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A token provider that obtains bearer tokens from an OAuth2 token endpoint using the {@code
 * client_credentials} grant, and refreshes them shortly before they expire.
 *
 * <p>This is the authentication mode expected by PDPs that are themselves OAuth2 authorization
 * servers -- most notably Keycloak, whose AuthZEN endpoints require an access token issued to a
 * client with authorization services enabled. Such tokens are short-lived, so a static or
 * file-based token is not a practical alternative.
 *
 * <p>The token lifetime is taken from the {@code expires_in} field of the token response; if that
 * is absent, the {@code exp} claim of the access token is used when it is a JWT. If neither is
 * available the provider falls back to a fixed refresh interval.
 */
public class ClientCredentialsTokenProvider implements BearerTokenProvider {

  private static final Logger LOGGER =
      LoggerFactory.getLogger(ClientCredentialsTokenProvider.class);

  private final URI tokenEndpoint;
  private final String clientId;
  private final String clientSecret;
  private final @Nullable String scope;
  private final Duration expirationBuffer;
  private final Duration fallbackRefreshInterval;
  private final Duration refreshRetryInterval;
  private final long initialTokenWaitMillis;
  private final CloseableHttpClient httpClient;
  private final ObjectMapper objectMapper;
  private final AsyncExec asyncExec;
  private final java.util.function.Supplier<Instant> clock;
  private final CompletableFuture<String> initialTokenFuture = new CompletableFuture<>();

  private volatile @Nullable String cachedToken;
  private volatile Instant nextRefresh = Instant.MIN;
  private volatile @Nullable Cancelable<?> refreshTask;
  private volatile boolean closed;

  // Guards a forced re-fetch triggered by a rejected token, so that a rejection seen by many
  // in-flight requests at once results in one token request rather than one per request.
  private final Object forcedRefreshLock = new Object();
  private volatile Instant lastForcedRefresh = Instant.MIN;

  /**
   * Creates a client-credentials token provider and immediately schedules the first token fetch.
   *
   * @param tokenEndpoint the OAuth2 token endpoint
   * @param clientId the OAuth2 client id
   * @param clientSecret the OAuth2 client secret
   * @param scope an optional space-delimited scope string
   * @param expirationBuffer how long before expiry the token is refreshed
   * @param fallbackRefreshInterval refresh interval used when the token lifetime is unknown
   * @param initialTokenWait how long {@link #getToken()} waits for the very first token
   * @param refreshRetryInterval how long to wait before retrying a failed token fetch
   * @param httpClient the HTTP client used to call the token endpoint
   * @param objectMapper Jackson mapper used to parse the token response
   * @param asyncExec asynchronous executor used to schedule refresh attempts
   * @param clock clock instance for time operations
   */
  public ClientCredentialsTokenProvider(
      URI tokenEndpoint,
      String clientId,
      String clientSecret,
      @Nullable String scope,
      Duration expirationBuffer,
      Duration fallbackRefreshInterval,
      Duration initialTokenWait,
      Duration refreshRetryInterval,
      CloseableHttpClient httpClient,
      ObjectMapper objectMapper,
      AsyncExec asyncExec,
      java.util.function.Supplier<Instant> clock) {
    checkArgument(!Strings.isNullOrEmpty(clientId), "clientId cannot be null or empty");
    checkArgument(!Strings.isNullOrEmpty(clientSecret), "clientSecret cannot be null or empty");
    this.tokenEndpoint = tokenEndpoint;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.scope = scope;
    this.expirationBuffer = expirationBuffer;
    this.fallbackRefreshInterval = fallbackRefreshInterval;
    this.refreshRetryInterval = refreshRetryInterval;
    this.initialTokenWaitMillis = initialTokenWait.toMillis();
    this.httpClient = httpClient;
    this.objectMapper = objectMapper;
    this.asyncExec = asyncExec;
    this.clock = clock;

    // Start fetching the token (immediately), so that the first authorization request does not
    // have to pay for it.
    scheduleRefreshAttempt(Duration.ZERO);
  }

  @Override
  public String getToken() {
    String token = cachedToken;
    if (token != null) {
      return token;
    }
    // The initial token has not been fetched yet; wait for the configured amount of time.
    try {
      return initialTokenFuture.get(initialTokenWaitMillis, TimeUnit.MILLISECONDS);
    } catch (Exception e) {
      throw new IllegalStateException(
          "Failed to obtain initial PDP bearer token from " + tokenEndpoint, e);
    }
  }

  @Override
  public void invalidate() {
    if (closed) {
      return;
    }
    String rejected = cachedToken;
    synchronized (forcedRefreshLock) {
      String current = cachedToken;
      if (current != null && !current.equals(rejected)) {
        // Another request hit the same rejection first and has already replaced it.
        return;
      }
      Instant now = clock.get();
      if (now.isBefore(lastForcedRefresh.plus(refreshRetryInterval))) {
        // Credentials that are simply wrong are rejected on every request, and fetching a
        // new token each time would turn one misconfiguration into a flood at the token
        // endpoint. One forced fetch per retry interval is enough to recover from a
        // rotation without becoming that flood.
        LOGGER.debug(
            "PDP bearer token was rejected again within {}, not re-fetching yet",
            refreshRetryInterval);
        return;
      }
      lastForcedRefresh = now;

      if (doRefreshToken()) {
        LOGGER.info(
            "Replaced the client-credentials token for client {} after it was rejected", clientId);
        // The scheduled refresh was aimed at the old token's expiry; re-aim it.
        Cancelable<?> task = refreshTask;
        if (task != null) {
          task.cancel();
        }
        scheduleRefreshAttempt(Duration.between(clock.get(), nextRefresh));
      }
    }
  }

  @Override
  public void close() {
    closed = true;
    cachedToken = null;
    Cancelable<?> task = refreshTask;
    if (task != null) {
      task.cancel();
    }
  }

  private void scheduleRefreshAttempt(Duration delay) {
    if (closed) {
      return;
    }
    refreshTask = asyncExec.schedule(this::refreshTokenAttempt, delay);
  }

  private void refreshTokenAttempt() {
    boolean isInitialRefresh = cachedToken == null;
    Duration delay;
    if (doRefreshToken()) {
      delay = Duration.between(clock.get(), nextRefresh);
      if (isInitialRefresh) {
        // Unblock getToken() call sites waiting for the very first token.
        initialTokenFuture.complete(cachedToken);
      }
    } else {
      delay = refreshRetryInterval;
    }
    scheduleRefreshAttempt(delay);
  }

  private boolean doRefreshToken() {
    try {
      TokenResponse response = requestToken();
      cachedToken = response.accessToken();
      nextRefresh = calculateNextRefresh(response);
      LOGGER.debug(
          "Obtained client-credentials token from {} for client {}, next refresh: {}",
          tokenEndpoint,
          clientId,
          nextRefresh);
      return true;
    } catch (Exception e) {
      LOGGER.warn(
          "Failed to obtain client-credentials token from {} for client {}, will retry in {}: {}",
          tokenEndpoint,
          clientId,
          refreshRetryInterval,
          e.toString());
      return false;
    }
  }

  private TokenResponse requestToken() throws IOException {
    List<NameValuePair> form = new ArrayList<>();
    form.add(new BasicNameValuePair("grant_type", "client_credentials"));
    form.add(new BasicNameValuePair("client_id", clientId));
    form.add(new BasicNameValuePair("client_secret", clientSecret));
    if (!Strings.isNullOrEmpty(scope)) {
      form.add(new BasicNameValuePair("scope", scope));
    }

    HttpPost post = new HttpPost(tokenEndpoint);
    post.setEntity(new UrlEncodedFormEntity(form, StandardCharsets.UTF_8));

    return httpClient.execute(post, this::parseTokenResponse);
  }

  private TokenResponse parseTokenResponse(ClassicHttpResponse response) throws IOException {
    int statusCode = response.getCode();
    String body;
    try {
      body = response.getEntity() == null ? "" : EntityUtils.toString(response.getEntity());
    } catch (org.apache.hc.core5.http.ParseException e) {
      throw new IOException("Failed to read token endpoint response", e);
    }
    if (statusCode != 200) {
      // The body of a failed token request can contain the client secret back in an error
      // description, so it is deliberately not logged here.
      throw new IOException("Token endpoint returned HTTP " + statusCode);
    }
    JsonNode node = objectMapper.readTree(body);
    String accessToken = node.path("access_token").asText(null);
    if (Strings.isNullOrEmpty(accessToken)) {
      throw new IOException("Token endpoint response did not contain an access_token");
    }
    long expiresIn = node.path("expires_in").asLong(0L);
    return new TokenResponse(accessToken, expiresIn > 0 ? Duration.ofSeconds(expiresIn) : null);
  }

  private Instant calculateNextRefresh(TokenResponse response) {
    Instant now = clock.get();
    Instant expiry =
        response.expiresIn() != null
            ? now.plus(response.expiresIn())
            : jwtExpiration(response.accessToken()).orElse(null);

    if (expiry == null) {
      LOGGER.debug(
          "Token endpoint did not report a lifetime and the token is not a JWT; using fixed refresh interval {}",
          fallbackRefreshInterval);
      return now.plus(fallbackRefreshInterval);
    }

    Instant refreshTime = expiry.minus(expirationBuffer);
    // Never schedule a refresh in the past, and never busy-loop on a token that is about to expire.
    Instant minRefreshTime = now.plus(Duration.ofSeconds(1));
    if (refreshTime.isBefore(minRefreshTime)) {
      LOGGER.warn(
          "Client-credentials token expires too soon ({}), refreshing in 1 second instead", expiry);
      return minRefreshTime;
    }
    return refreshTime;
  }

  private Optional<Instant> jwtExpiration(String token) {
    try {
      Date expiresAt = JWT.decode(token).getExpiresAt();
      return expiresAt != null ? Optional.of(expiresAt.toInstant()) : Optional.empty();
    } catch (JWTDecodeException e) {
      return Optional.empty();
    }
  }

  private record TokenResponse(String accessToken, @Nullable Duration expiresIn) {}
}
