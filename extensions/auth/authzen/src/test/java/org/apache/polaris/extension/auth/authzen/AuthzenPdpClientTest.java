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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.json.JsonMapper;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.polaris.extension.auth.authzen.model.AuthzenEvaluationRequest;
import org.apache.polaris.extension.auth.authzen.model.ImmutableAuthzenAction;
import org.apache.polaris.extension.auth.authzen.model.ImmutableAuthzenContext;
import org.apache.polaris.extension.auth.authzen.model.ImmutableAuthzenEvaluationRequest;
import org.apache.polaris.extension.auth.authzen.model.ImmutableAuthzenResource;
import org.apache.polaris.extension.auth.authzen.model.ImmutableAuthzenResourceProperties;
import org.apache.polaris.extension.auth.authzen.model.ImmutableAuthzenSubject;
import org.apache.polaris.extension.auth.authzen.model.ImmutableAuthzenSubjectProperties;
import org.apache.polaris.extension.auth.common.config.ImmutablePdpHttpConfig;
import org.apache.polaris.extension.auth.common.token.BearerTokenProvider;
import org.junit.jupiter.api.Test;

public class AuthzenPdpClientTest {

  private static ImmutableAuthzenAuthorizationConfig.Builder config() {
    return ImmutableAuthzenAuthorizationConfig.builder()
        .useBatchEndpoint(true)
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
            ImmutablePdpHttpConfig.builder()
                .timeout(Duration.ofSeconds(2))
                .verifySsl(true)
                .build());
  }

  @Test
  void appendsTheWellKnownPathWithoutSwallowingTheBasePath() {
    // URI.resolve() would turn ".../realms/demo" into ".../realms/.well-known/..."
    assertThat(AuthzenPdpClient.discoveryUri(URI.create("https://kc.example.com/realms/demo")))
        .isEqualTo(
            URI.create("https://kc.example.com/realms/demo/.well-known/authzen-configuration"));

    assertThat(AuthzenPdpClient.discoveryUri(URI.create("https://kc.example.com/realms/demo/")))
        .isEqualTo(
            URI.create("https://kc.example.com/realms/demo/.well-known/authzen-configuration"));
  }

  @Test
  void discoversEndpointsFromThePdpMetadata() throws Exception {
    try (StubAuthzenPdp pdp = new StubAuthzenPdp();
        CloseableHttpClient httpClient = HttpClients.createDefault()) {
      AuthzenPdpClient client =
          new AuthzenPdpClient(
              config().pdpUri(pdp.pdpUri()).build(),
              httpClient,
              JsonMapper.builder().build(),
              null);

      AuthzenPdpClient.Endpoints endpoints = client.endpoints();
      assertThat(endpoints.evaluation()).isEqualTo(pdp.pdpUri().resolve("/access/v1/evaluation"));
      assertThat(endpoints.evaluations()).isEqualTo(pdp.pdpUri().resolve("/access/v1/evaluations"));
      assertThat(client.batchEnabled()).isTrue();
    }
  }

  @Test
  void explicitEndpointsWinOverDiscovery() throws Exception {
    try (StubAuthzenPdp pdp = new StubAuthzenPdp();
        CloseableHttpClient httpClient = HttpClients.createDefault()) {
      URI explicit = URI.create("https://elsewhere.example.com/eval");
      AuthzenPdpClient client =
          new AuthzenPdpClient(
              config()
                  .pdpUri(pdp.pdpUri())
                  .accessEvaluationEndpoint(explicit)
                  .accessEvaluationsEndpoint(URI.create("https://elsewhere.example.com/evals"))
                  .build(),
              httpClient,
              JsonMapper.builder().build(),
              null);

      assertThat(client.endpoints().evaluation()).isEqualTo(explicit);
    }
  }

  @Test
  void reportsNoBatchSupportWhenThePdpDoesNotAdvertiseIt() throws Exception {
    try (StubAuthzenPdp pdp = new StubAuthzenPdp(false);
        CloseableHttpClient httpClient = HttpClients.createDefault()) {
      AuthzenPdpClient client =
          new AuthzenPdpClient(
              config().pdpUri(pdp.pdpUri()).build(),
              httpClient,
              JsonMapper.builder().build(),
              null);

      assertThat(client.endpoints().evaluations()).isNull();
      assertThat(client.batchEnabled()).isFalse();
    }
  }

  @Test
  void failsWhenTheEndpointsCannotBeResolved() throws Exception {
    try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
      AuthzenPdpClient client =
          new AuthzenPdpClient(
              config().pdpUri(URI.create("http://127.0.0.1:1/realms/demo")).build(),
              httpClient,
              JsonMapper.builder().build(),
              null);

      assertThatThrownBy(client::endpoints)
          .isInstanceOf(RuntimeException.class)
          .hasMessageContaining("Failed to fetch AuthZEN PDP metadata");
    }
  }

  /**
   * A PDP that answers 401 is refusing the credential, not deciding the question. Treating that as
   * a deny is wrong twice over: the request is refused, and nothing ever tells the token provider
   * that what it holds has stopped being accepted -- so the deny is permanent.
   */
  @Test
  void replacesARejectedBearerTokenAndAsksAgain() throws Exception {
    try (StubAuthzenPdp pdp = new StubAuthzenPdp();
        CloseableHttpClient httpClient = HttpClients.createDefault()) {
      SequencedTokenProvider tokens = new SequencedTokenProvider("stale", "fresh");
      AuthzenPdpClient client =
          new AuthzenPdpClient(
              config().pdpUri(pdp.pdpUri()).build(),
              httpClient,
              JsonMapper.builder().build(),
              tokens);

      // Rejected once -- as after the authorization server's signing keys are rotated --
      // and answered normally thereafter.
      pdp.onNextEvaluation(401, "{\"error\":\"HTTP 401 Unauthorized\"}");

      assertThat(client.evaluate(evaluationRequest(), "req-1")).isTrue();

      assertThat(tokens.invalidations()).isEqualTo(1);
      assertThat(pdp.requestHeaders()).hasSize(2);
      assertThat(pdp.requestHeaders().get(0)).containsEntry("Authorization", "Bearer stale");
      assertThat(pdp.requestHeaders().get(1)).containsEntry("Authorization", "Bearer fresh");
    }
  }

  @Test
  void deniesWhenTheReplacementTokenIsRejectedToo() throws Exception {
    try (StubAuthzenPdp pdp = new StubAuthzenPdp();
        CloseableHttpClient httpClient = HttpClients.createDefault()) {
      SequencedTokenProvider tokens = new SequencedTokenProvider("stale", "fresh");
      AuthzenPdpClient client =
          new AuthzenPdpClient(
              config().pdpUri(pdp.pdpUri()).build(),
              httpClient,
              JsonMapper.builder().build(),
              tokens);

      // Every attempt is refused: the credential or the policy is wrong, not the token's age.
      pdp.onEvaluation(401, "{\"error\":\"HTTP 401 Unauthorized\"}");

      assertThat(client.evaluate(evaluationRequest(), "req-1")).isFalse();

      // Retried exactly once, and the token replaced exactly once.
      assertThat(pdp.requestHeaders()).hasSize(2);
      assertThat(tokens.invalidations()).isEqualTo(1);
    }
  }

  @Test
  void doesNotRetryA403() throws Exception {
    try (StubAuthzenPdp pdp = new StubAuthzenPdp();
        CloseableHttpClient httpClient = HttpClients.createDefault()) {
      SequencedTokenProvider tokens = new SequencedTokenProvider("stale", "fresh");
      AuthzenPdpClient client =
          new AuthzenPdpClient(
              config().pdpUri(pdp.pdpUri()).build(),
              httpClient,
              JsonMapper.builder().build(),
              tokens);

      // A PDP may use 403 to say this client may not ask at all, which a new token
      // would not change.
      pdp.onEvaluation(403, "{\"error\":\"forbidden\"}");

      assertThat(client.evaluate(evaluationRequest(), "req-1")).isFalse();

      assertThat(pdp.requestHeaders()).hasSize(1);
      assertThat(tokens.invalidations()).isZero();
    }
  }

  private static AuthzenEvaluationRequest evaluationRequest() {
    return ImmutableAuthzenEvaluationRequest.builder()
        .subject(
            ImmutableAuthzenSubject.builder()
                .type("user")
                .id("alice")
                .properties(
                    ImmutableAuthzenSubjectProperties.builder()
                        .addRoles("data_engineer")
                        .realm("POLARIS")
                        .build())
                .build())
        .action(ImmutableAuthzenAction.builder().name("LOAD_TABLE").build())
        .resource(
            ImmutableAuthzenResource.builder()
                .type("polaris:TABLE_LIKE")
                .id("events")
                .properties(ImmutableAuthzenResourceProperties.builder().name("events").build())
                .build())
        .context(ImmutableAuthzenContext.builder().requestId("req-1").realm("POLARIS").build())
        .build();
  }

  /** Hands out the next token each time it is told the previous one was refused. */
  private static final class SequencedTokenProvider implements BearerTokenProvider {
    private final List<String> tokens;
    private final AtomicInteger index = new AtomicInteger();
    private final AtomicInteger invalidations = new AtomicInteger();

    SequencedTokenProvider(String... tokens) {
      this.tokens = List.of(tokens);
    }

    @Override
    public String getToken() {
      return tokens.get(Math.min(index.get(), tokens.size() - 1));
    }

    @Override
    public void invalidate() {
      invalidations.incrementAndGet();
      index.incrementAndGet();
    }

    int invalidations() {
      return invalidations.get();
    }
  }

  @Test
  void warmUpDoesNotFailWhenThePdpIsUnreachable() throws Exception {
    try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
      AuthzenPdpClient client =
          new AuthzenPdpClient(
              config().pdpUri(URI.create("http://127.0.0.1:1/realms/demo")).build(),
              httpClient,
              JsonMapper.builder().build(),
              null);

      // startup must not depend on the PDP being up; discovery is retried on first use
      client.warmUp();
    }
  }
}
