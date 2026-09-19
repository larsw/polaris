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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.polaris.core.auth.AuthorizationDecision;
import org.apache.polaris.core.auth.AuthorizationIntent;
import org.apache.polaris.core.auth.AuthorizationRequest;
import org.apache.polaris.core.auth.AuthorizationState;
import org.apache.polaris.core.auth.PathSegment;
import org.apache.polaris.core.auth.PolarisAuthorizableOperation;
import org.apache.polaris.core.auth.PolarisPrincipal;
import org.apache.polaris.core.auth.PolarisSecurable;
import org.apache.polaris.core.auth.SingleTargetAuthorizationIntent;
import org.apache.polaris.core.auth.TargetlessAuthorizationIntent;
import org.apache.polaris.core.entity.PolarisEntityType;
import org.apache.polaris.core.persistence.resolver.PolarisResolutionManifest;
import org.apache.polaris.extension.auth.common.config.ImmutablePdpHttpConfig;
import org.apache.polaris.extension.auth.common.token.StaticBearerTokenProvider;
import org.junit.jupiter.api.Test;

/** Verifies how the AuthZEN authorizer turns PDP answers into Polaris decisions. */
public class AuthzenPolarisAuthorizerTest {

  private static final ObjectMapper MAPPER = JsonMapper.builder().build();

  private static final PolarisPrincipal ALICE =
      PolarisPrincipal.of("alice", Map.of(), Set.of("analyst"));

  private static final PolarisSecurable CATALOG =
      PolarisSecurable.of(new PathSegment(PolarisEntityType.CATALOG, "prod_catalog"));

  private static final PolarisSecurable OTHER_CATALOG =
      PolarisSecurable.of(new PathSegment(PolarisEntityType.CATALOG, "dev_catalog"));

  private static AuthorizationRequest request(AuthorizationIntent... intents) {
    return new AuthorizationRequest(ALICE, List.of(intents));
  }

  private static AuthorizationIntent listCatalogs() {
    return new TargetlessAuthorizationIntent(PolarisAuthorizableOperation.LIST_CATALOGS);
  }

  private static AuthorizationIntent getCatalog(PolarisSecurable catalog) {
    return new SingleTargetAuthorizationIntent(PolarisAuthorizableOperation.GET_CATALOG, catalog);
  }

  private static AuthzenAuthorizationConfig config(StubAuthzenPdp pdp, boolean batch) {
    return ImmutableAuthzenAuthorizationConfig.builder()
        .pdpUri(pdp.pdpUri())
        .useBatchEndpoint(batch)
        .mapping(
            ImmutableMappingConfig.builder()
                .subjectType("user")
                .resourceIdFormat(AuthzenAuthorizationConfig.ResourceIdFormat.PATH)
                .resourceIdSeparator("/")
                .actionNameCase(AuthzenAuthorizationConfig.ActionNameCase.AS_IS)
                .rootResourceType("ROOT")
                .build())
        .auth(
            ImmutableAuthenticationConfig.builder()
                .type(AuthzenAuthorizationConfig.AuthenticationType.NONE)
                .build())
        .http(
            ImmutablePdpHttpConfig.builder().timeout(Duration.ofSeconds(5)).verifySsl(true).build())
        .build();
  }

  private AuthorizationDecision authorize(
      StubAuthzenPdp pdp, boolean batch, AuthorizationRequest request) {
    return authorize(pdp, batch, request, null);
  }

  private AuthorizationDecision authorize(
      StubAuthzenPdp pdp, boolean batch, AuthorizationRequest request, String bearerToken) {
    AuthzenAuthorizationConfig config = config(pdp, batch);
    try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
      AuthzenPdpClient client =
          new AuthzenPdpClient(
              config,
              httpClient,
              MAPPER,
              bearerToken == null ? null : new StaticBearerTokenProvider(bearerToken));
      AuthzenPolarisAuthorizer authorizer =
          new AuthzenPolarisAuthorizer(
              client,
              new AuthzenRequestBuilder(config.mapping(), "prod-realm"),
              "req-42",
              "prod-realm");
      return authorizer.authorize(
          new AuthorizationState(mock(PolarisResolutionManifest.class)), request);
    } catch (java.io.IOException e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  void allowsWhenPdpPermitsTheOnlyIntent() throws Exception {
    try (StubAuthzenPdp pdp = new StubAuthzenPdp()) {
      pdp.onEvaluation(200, "{\"decision\":true}");

      assertThat(authorize(pdp, true, request(listCatalogs())).isAllowed()).isTrue();
      // a single intent goes to the single-evaluation endpoint, even with batching enabled
      assertThat(pdp.requestBodies()).hasSize(1);
      assertThat(MAPPER.readTree(pdp.requestBodies().get(0)).has("evaluations")).isFalse();
    }
  }

  @Test
  void deniesWhenPdpDeniesTheOnlyIntent() throws Exception {
    try (StubAuthzenPdp pdp = new StubAuthzenPdp()) {
      pdp.onEvaluation(200, "{\"decision\":false}");

      AuthorizationDecision decision = authorize(pdp, true, request(listCatalogs()));
      assertThat(decision.isAllowed()).isFalse();
      assertThat(decision.getMessage()).contains("AuthZEN PDP denied authorization");
    }
  }

  @Test
  void batchesSeveralIntentsIntoOneCall() throws Exception {
    try (StubAuthzenPdp pdp = new StubAuthzenPdp()) {
      pdp.onEvaluations(200, "{\"evaluations\":[{\"decision\":true},{\"decision\":true}]}");

      assertThat(
              authorize(pdp, true, request(getCatalog(CATALOG), getCatalog(OTHER_CATALOG)))
                  .isAllowed())
          .isTrue();
      assertThat(pdp.requestBodies()).hasSize(1);
      JsonNode body = MAPPER.readTree(pdp.requestBodies().get(0));
      assertThat(body.get("evaluations").size()).isEqualTo(2);
      assertThat(body.get("options").get("evaluations_semantic").asText())
          .isEqualTo("deny_on_first_deny");
    }
  }

  @Test
  void deniesWhenAnyBatchedDecisionIsDeny() throws Exception {
    try (StubAuthzenPdp pdp = new StubAuthzenPdp()) {
      pdp.onEvaluations(200, "{\"evaluations\":[{\"decision\":true},{\"decision\":false}]}");

      assertThat(
              authorize(pdp, true, request(getCatalog(CATALOG), getCatalog(OTHER_CATALOG)))
                  .isAllowed())
          .isFalse();
    }
  }

  @Test
  void acceptsATruncatedBatchThatEndsInADeny() throws Exception {
    try (StubAuthzenPdp pdp = new StubAuthzenPdp()) {
      // deny_on_first_deny lets the PDP stop early; Keycloak answers exactly like this
      pdp.onEvaluations(
          200,
          "{\"evaluations\":[{\"decision\":true},{\"decision\":false,\"context\":{\"reason\":\"deny_on_first_deny\"}}]}");

      assertThat(
              authorize(
                      pdp,
                      true,
                      request(getCatalog(CATALOG), getCatalog(OTHER_CATALOG), listCatalogs()))
                  .isAllowed())
          .isFalse();
    }
  }

  @Test
  void deniesWhenATruncatedBatchEndsInAPermit() throws Exception {
    try (StubAuthzenPdp pdp = new StubAuthzenPdp()) {
      // fewer decisions than intents without a deny means intents went unevaluated: fail closed
      pdp.onEvaluations(200, "{\"evaluations\":[{\"decision\":true}]}");

      assertThat(
              authorize(pdp, true, request(getCatalog(CATALOG), getCatalog(OTHER_CATALOG)))
                  .isAllowed())
          .isFalse();
    }
  }

  @Test
  void deniesWhenTheBatchReturnsMoreDecisionsThanIntents() throws Exception {
    try (StubAuthzenPdp pdp = new StubAuthzenPdp()) {
      pdp.onEvaluations(
          200, "{\"evaluations\":[{\"decision\":true},{\"decision\":true},{\"decision\":true}]}");

      assertThat(
              authorize(pdp, true, request(getCatalog(CATALOG), getCatalog(OTHER_CATALOG)))
                  .isAllowed())
          .isFalse();
    }
  }

  @Test
  void deniesWhenTheBatchResponseHasNoEvaluationsArray() throws Exception {
    try (StubAuthzenPdp pdp = new StubAuthzenPdp()) {
      pdp.onEvaluations(200, "{\"decision\":true}");

      assertThat(
              authorize(pdp, true, request(getCatalog(CATALOG), getCatalog(OTHER_CATALOG)))
                  .isAllowed())
          .isFalse();
    }
  }

  @Test
  void deniesOnNonSuccessStatus() throws Exception {
    try (StubAuthzenPdp pdp = new StubAuthzenPdp()) {
      pdp.onEvaluation(403, "{\"error\":\"forbidden\"}");

      assertThat(authorize(pdp, true, request(listCatalogs())).isAllowed()).isFalse();
    }
  }

  @Test
  void deniesWhenTheDecisionFieldIsMissingOrNotBoolean() throws Exception {
    try (StubAuthzenPdp pdp = new StubAuthzenPdp()) {
      pdp.onEvaluation(200, "{\"context\":{\"reason_user\":\"nope\"}}");
      assertThat(authorize(pdp, true, request(listCatalogs())).isAllowed()).isFalse();

      pdp.onEvaluation(200, "{\"decision\":\"true\"}");
      assertThat(authorize(pdp, true, request(listCatalogs())).isAllowed()).isFalse();
    }
  }

  @Test
  void fallsBackToOneCallPerIntentWhenBatchingIsDisabled() throws Exception {
    try (StubAuthzenPdp pdp = new StubAuthzenPdp()) {
      pdp.onEvaluation(200, "{\"decision\":true}");

      assertThat(
              authorize(pdp, false, request(getCatalog(CATALOG), getCatalog(OTHER_CATALOG)))
                  .isAllowed())
          .isTrue();
      assertThat(pdp.requestBodies()).hasSize(2);
    }
  }

  @Test
  void fallsBackToOneCallPerIntentWhenThePdpAdvertisesNoBatchEndpoint() throws Exception {
    try (StubAuthzenPdp pdp = new StubAuthzenPdp(false)) {
      pdp.onEvaluation(200, "{\"decision\":true}");

      assertThat(
              authorize(pdp, true, request(getCatalog(CATALOG), getCatalog(OTHER_CATALOG)))
                  .isAllowed())
          .isTrue();
      assertThat(pdp.requestBodies()).hasSize(2);
    }
  }

  @Test
  void shortCircuitsAtTheFirstDenyWhenCallingOneByOne() throws Exception {
    try (StubAuthzenPdp pdp = new StubAuthzenPdp()) {
      pdp.onEvaluation(200, "{\"decision\":false}");

      assertThat(
              authorize(pdp, false, request(getCatalog(CATALOG), getCatalog(OTHER_CATALOG)))
                  .isAllowed())
          .isFalse();
      assertThat(pdp.requestBodies()).hasSize(1);
    }
  }

  @Test
  void sendsBearerTokenAndRequestIdHeaders() throws Exception {
    try (StubAuthzenPdp pdp = new StubAuthzenPdp()) {
      pdp.onEvaluation(200, "{\"decision\":true}");

      authorize(pdp, true, request(listCatalogs()), "pdp-token");

      Map<String, String> headers = pdp.requestHeaders().get(0);
      assertThat(headers.get("Authorization")).isEqualTo("Bearer pdp-token");
      assertThat(headers.get("X-request-id")).isEqualTo("req-42");
    }
  }
}
