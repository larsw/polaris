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
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.polaris.extension.auth.common.config.ImmutablePdpHttpConfig;
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
