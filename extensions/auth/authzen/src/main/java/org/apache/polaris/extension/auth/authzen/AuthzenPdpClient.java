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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.annotations.VisibleForTesting;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.polaris.extension.auth.authzen.model.AuthzenEvaluationRequest;
import org.apache.polaris.extension.auth.authzen.model.AuthzenEvaluationsRequest;
import org.apache.polaris.extension.auth.common.token.BearerTokenProvider;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Talks to an AuthZEN Policy Decision Point: resolves its endpoints, posts evaluation requests and
 * reads back decisions.
 *
 * <p>Responses are parsed with Jackson's tree API rather than mapped onto model classes, because
 * the AuthZEN specification permits a PDP to return additional fields and an unknown field must not
 * turn an allow into an error.
 *
 * @see <a href="https://openid.net/specs/authorization-api-1_0.html">AuthZEN Authorization API
 *     1.0</a>
 */
class AuthzenPdpClient {

  private static final Logger LOGGER = LoggerFactory.getLogger(AuthzenPdpClient.class);

  private static final String WELL_KNOWN_PATH = ".well-known/authzen-configuration";
  private static final String REQUEST_ID_HEADER = "X-Request-ID";

  private final AuthzenAuthorizationConfig config;
  private final CloseableHttpClient httpClient;
  private final ObjectMapper objectMapper;
  private final @Nullable BearerTokenProvider tokenProvider;

  private volatile @Nullable Endpoints endpoints;

  AuthzenPdpClient(
      AuthzenAuthorizationConfig config,
      CloseableHttpClient httpClient,
      ObjectMapper objectMapper,
      @Nullable BearerTokenProvider tokenProvider) {
    this.config = config;
    this.httpClient = httpClient;
    this.objectMapper = objectMapper;
    this.tokenProvider = tokenProvider;
  }

  /** The resolved PDP endpoints, discovering them from the PDP metadata on first use. */
  Endpoints endpoints() {
    Endpoints resolved = endpoints;
    if (resolved == null) {
      synchronized (this) {
        resolved = endpoints;
        if (resolved == null) {
          resolved = resolveEndpoints();
          endpoints = resolved;
        }
      }
    }
    return resolved;
  }

  /**
   * Eagerly resolves the endpoints, swallowing failures.
   *
   * <p>Called at startup so that a reachable PDP is discovered before the first request pays for
   * it, while a PDP that happens to be down does not prevent Polaris from starting -- discovery is
   * retried on first use.
   */
  void warmUp() {
    try {
      Endpoints resolved = endpoints();
      LOGGER.info(
          "Resolved AuthZEN endpoints: evaluation={}, evaluations={}",
          resolved.evaluation(),
          resolved.evaluations());
    } catch (RuntimeException e) {
      LOGGER.warn(
          "Could not resolve AuthZEN PDP endpoints at startup, will retry on first authorization request: {}",
          e.toString());
    }
  }

  /**
   * Posts a single Access Evaluation request.
   *
   * @return the PDP decision; {@code false} if the PDP answered with anything other than a
   *     well-formed permit
   */
  boolean evaluate(AuthzenEvaluationRequest request, @Nullable String requestId) {
    JsonNode response = post(endpoints().evaluation(), request, requestId);
    if (response == null) {
      return false;
    }
    return decisionOf(response);
  }

  /**
   * Posts a batched Access Evaluations request.
   *
   * @return the decisions in request order. The list may be shorter than the number of evaluations
   *     sent, because {@code deny_on_first_deny} lets the PDP stop early; it is empty when the PDP
   *     could not be understood.
   */
  List<Boolean> evaluations(AuthzenEvaluationsRequest request, @Nullable String requestId) {
    URI endpoint = endpoints().evaluations();
    if (endpoint == null) {
      throw new IllegalStateException("No AuthZEN Access Evaluations endpoint is configured");
    }
    JsonNode response = post(endpoint, request, requestId);
    if (response == null) {
      return List.of();
    }
    JsonNode evaluations = response.path("evaluations");
    if (!evaluations.isArray()) {
      LOGGER.warn("AuthZEN PDP response did not contain an 'evaluations' array, treating as deny");
      return List.of();
    }
    List<Boolean> decisions = new ArrayList<>(evaluations.size());
    for (JsonNode evaluation : evaluations) {
      decisions.add(decisionOf(evaluation));
    }
    return decisions;
  }

  /** Whether a batch endpoint is available and batching is enabled. */
  boolean batchEnabled() {
    return config.useBatchEndpoint() && endpoints().evaluations() != null;
  }

  private static boolean decisionOf(JsonNode node) {
    JsonNode decision = node.path("decision");
    if (!decision.isBoolean()) {
      LOGGER.warn("AuthZEN PDP response had no boolean 'decision' field, treating as deny");
      return false;
    }
    return decision.booleanValue();
  }

  /** Returns the parsed response body, or {@code null} if the PDP did not answer with HTTP 200. */
  private @Nullable JsonNode post(URI endpoint, Object body, @Nullable String requestId) {
    try {
      String json = objectMapper.writeValueAsString(body);
      // The exact strings matter, because that is what a PDP matches on, and a mismatch is
      // otherwise only visible with a packet capture. DEBUG rather than TRACE: Quarkus caps
      // runtime levels at its build-time minimum, which is DEBUG, so a TRACE line could not be
      // switched on in a distributed build. The payload names principals, roles and resources,
      // which the denial log at this level already does.
      LOGGER.debug("POST {} {}", endpoint, json);
      HttpPost httpPost = new HttpPost(endpoint);
      httpPost.setEntity(new StringEntity(json, ContentType.APPLICATION_JSON));
      applyCommonHeaders(httpPost, requestId);
      return httpClientExecute(httpPost, response -> readJson(response, endpoint));
    } catch (IOException e) {
      throw new RuntimeException("AuthZEN access evaluation failed", e);
    }
  }

  private Endpoints resolveEndpoints() {
    URI evaluation = config.accessEvaluationEndpoint().orElse(null);
    URI evaluations = config.accessEvaluationsEndpoint().orElse(null);

    boolean needsBatch = config.useBatchEndpoint() && evaluations == null;
    if ((evaluation == null || needsBatch) && config.pdpUri().isPresent()) {
      PdpMetadata metadata = fetchMetadata(config.pdpUri().get());
      if (evaluation == null) {
        evaluation = metadata.evaluation();
      }
      if (evaluations == null) {
        evaluations = metadata.evaluations();
      }
    }

    if (evaluation == null) {
      throw new IllegalStateException(
          "The AuthZEN PDP did not advertise an access_evaluation_endpoint; configure "
              + "polaris.authorization.authzen.access-evaluation-endpoint explicitly");
    }
    return new Endpoints(evaluation, evaluations);
  }

  private PdpMetadata fetchMetadata(URI pdpUri) {
    URI discoveryUri = discoveryUri(pdpUri);
    try {
      HttpGet httpGet = new HttpGet(discoveryUri);
      applyCommonHeaders(httpGet, null);
      JsonNode metadata = httpClientExecute(httpGet, response -> readJson(response, discoveryUri));
      if (metadata == null) {
        throw new IllegalStateException(
            "AuthZEN PDP metadata request to " + discoveryUri + " did not return HTTP 200");
      }
      return new PdpMetadata(
          uriOrNull(metadata, "access_evaluation_endpoint"),
          uriOrNull(metadata, "access_evaluations_endpoint"));
    } catch (IOException e) {
      throw new RuntimeException("Failed to fetch AuthZEN PDP metadata from " + discoveryUri, e);
    }
  }

  @VisibleForTesting
  static URI discoveryUri(URI pdpUri) {
    // Deliberately not URI.resolve(): the PDP URI is a base path (a Keycloak realm, say), and
    // resolving a relative reference against it would drop its last segment.
    String base = pdpUri.toString();
    return URI.create(base.endsWith("/") ? base + WELL_KNOWN_PATH : base + "/" + WELL_KNOWN_PATH);
  }

  private static @Nullable URI uriOrNull(JsonNode metadata, String field) {
    String value = metadata.path(field).asText(null);
    return value == null || value.isEmpty() ? null : URI.create(value);
  }

  private void applyCommonHeaders(ClassicHttpRequest request, @Nullable String requestId) {
    request.setHeader(HttpHeaders.ACCEPT, ContentType.APPLICATION_JSON.getMimeType());
    if (requestId != null) {
      request.setHeader(REQUEST_ID_HEADER, requestId);
    }
    if (tokenProvider != null) {
      String token = tokenProvider.getToken();
      if (token != null && !token.isEmpty()) {
        request.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token);
      }
    }
  }

  private @Nullable JsonNode readJson(ClassicHttpResponse response, URI endpoint)
      throws IOException {
    int statusCode = response.getCode();
    String responseBody;
    try {
      responseBody = response.getEntity() == null ? "" : EntityUtils.toString(response.getEntity());
    } catch (ParseException e) {
      throw new IOException("Failed to parse AuthZEN PDP response", e);
    }
    if (statusCode != 200) {
      // A PDP explains a rejected request in the body, which is what makes a payload mismatch
      // diagnosable; it is not expected to contain anything sensitive.
      LOGGER.warn(
          "AuthZEN PDP at {} returned unexpected HTTP status {}, treating as deny: {}",
          endpoint,
          statusCode,
          responseBody);
      return null;
    }
    LOGGER.debug("AuthZEN PDP at {} answered {}", endpoint, responseBody);
    return objectMapper.readTree(responseBody);
  }

  @VisibleForTesting
  <T> T httpClientExecute(
      ClassicHttpRequest request, HttpClientResponseHandler<? extends T> responseHandler)
      throws IOException {
    return httpClient.execute(request, responseHandler);
  }

  /** The AuthZEN endpoints in use, however they were resolved. */
  record Endpoints(URI evaluation, @Nullable URI evaluations) {}

  private record PdpMetadata(@Nullable URI evaluation, @Nullable URI evaluations) {}
}
