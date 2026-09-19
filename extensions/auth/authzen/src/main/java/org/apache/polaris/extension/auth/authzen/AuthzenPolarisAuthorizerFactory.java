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
package org.apache.polaris.extension.auth.authzen;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import io.smallrye.common.annotation.Identifier;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.polaris.core.auth.PolarisAuthorizer;
import org.apache.polaris.core.auth.PolarisAuthorizerFactory;
import org.apache.polaris.core.config.RealmConfig;
import org.apache.polaris.core.context.RealmContext;
import org.apache.polaris.core.context.RequestIdSupplier;
import org.apache.polaris.extension.auth.common.http.PdpHttpClientFactory;
import org.apache.polaris.extension.auth.common.token.BearerTokenProvider;
import org.apache.polaris.extension.auth.common.token.BearerTokenProviders;
import org.apache.polaris.extension.auth.common.token.ClientCredentialsTokenProvider;
import org.apache.polaris.nosql.async.AsyncExec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Factory for creating AuthZEN-based Polaris authorizer implementations. */
@ApplicationScoped
@Identifier("authzen")
class AuthzenPolarisAuthorizerFactory implements PolarisAuthorizerFactory {

  private static final Logger LOGGER =
      LoggerFactory.getLogger(AuthzenPolarisAuthorizerFactory.class);

  private final AuthzenAuthorizationConfig authzenConfig;
  private final Clock clock;
  private final ObjectMapper objectMapper;
  private final AsyncExec asyncExec;
  private final RequestIdSupplier requestIdSupplier;
  private final RealmContext realmContext;
  private CloseableHttpClient httpClient;
  private BearerTokenProvider tokenProvider;
  private AuthzenPdpClient pdpClient;

  @Inject
  public AuthzenPolarisAuthorizerFactory(
      AuthzenAuthorizationConfig authzenConfig,
      Clock clock,
      AsyncExec asyncExec,
      RequestIdSupplier requestIdSupplier,
      RealmContext realmContext) {
    this.authzenConfig = authzenConfig;
    this.clock = clock;
    this.asyncExec = asyncExec;
    this.requestIdSupplier = requestIdSupplier;
    this.realmContext = realmContext;
    this.objectMapper = JsonMapper.builder().build();
  }

  /**
   * Gets the AuthZEN authorization configuration. Used by {@link AuthzenProductionReadinessChecks}.
   *
   * @return the AuthZEN configuration
   */
  AuthzenAuthorizationConfig getConfig() {
    return authzenConfig;
  }

  @PostConstruct
  public void initialize() {
    authzenConfig.validate();

    httpClient = createHttpClient();
    tokenProvider = createTokenProvider();
    pdpClient = new AuthzenPdpClient(authzenConfig, httpClient, objectMapper, tokenProvider);

    // Resolve the endpoints now, so a misconfigured PDP shows up in the logs at startup rather
    // than on the first authorization request. A PDP that is merely unreachable right now does
    // not fail startup; discovery is retried lazily.
    pdpClient.warmUp();
  }

  @Override
  public PolarisAuthorizer create(RealmConfig realmConfig) {
    String realm = realmContext.getRealmIdentifier();
    return new AuthzenPolarisAuthorizer(
        pdpClient,
        new AuthzenRequestBuilder(authzenConfig.mapping(), realm),
        requestIdSupplier.getRequestId(),
        realm);
  }

  @PreDestroy
  public void cleanup() {
    if (tokenProvider != null) {
      try {
        tokenProvider.close();
        LOGGER.debug("Token provider closed successfully");
      } catch (Exception e) {
        // Log but don't throw - we're shutting down anyway
        LOGGER.warn("Error closing token provider: {}", e.getMessage(), e);
      }
    }

    if (httpClient != null) {
      try {
        httpClient.close();
        LOGGER.debug("HTTP client closed successfully");
      } catch (IOException e) {
        // Log but don't throw - we're shutting down anyway
        LOGGER.warn("Error closing HTTP client: {}", e.getMessage(), e);
      }
    }
  }

  private CloseableHttpClient createHttpClient() {
    try {
      return PdpHttpClientFactory.createHttpClient(authzenConfig.http());
    } catch (RuntimeException e) {
      // Misconfigured truststore/timeout/SSL must fail startup rather than silently falling back
      // to a default client (system trust, no response timeout).
      throw new IllegalStateException("Failed to create HTTP client for AuthZEN communication", e);
    }
  }

  private BearerTokenProvider createTokenProvider() {
    AuthzenAuthorizationConfig.AuthenticationConfig authConfig = authzenConfig.auth();
    switch (authConfig.type()) {
      case BEARER:
        if (authConfig.bearer().isEmpty()) {
          throw new IllegalStateException("Bearer configuration is required when type is 'bearer'");
        }
        return BearerTokenProviders.create(authConfig.bearer().get(), asyncExec, clock);
      case CLIENT_CREDENTIALS:
        if (authConfig.clientCredentials().isEmpty()) {
          throw new IllegalStateException(
              "Client credentials configuration is required when type is 'client-credentials'");
        }
        return createClientCredentialsProvider(authConfig.clientCredentials().get());
      case NONE:
        return null; // No authentication
      default:
        throw new IllegalStateException("Unsupported authentication type: " + authConfig.type());
    }
  }

  private BearerTokenProvider createClientCredentialsProvider(
      AuthzenAuthorizationConfig.ClientCredentialsConfig config) {
    return new ClientCredentialsTokenProvider(
        config.tokenEndpoint(),
        config.clientId(),
        config.clientSecret(),
        config.scope().orElse(null),
        config.expirationBuffer().orElse(Duration.ofMinutes(1)),
        config.refreshInterval().orElse(Duration.ofMinutes(5)),
        config.initialTokenWait().orElse(Duration.ofSeconds(5)),
        config.refreshRetryInterval().orElse(Duration.ofSeconds(1)),
        httpClient,
        objectMapper,
        asyncExec,
        clock::instant);
  }
}
