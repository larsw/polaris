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

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.time.Duration;
import org.apache.polaris.extension.auth.common.config.ImmutableBearerTokenConfig;
import org.apache.polaris.extension.auth.common.config.ImmutablePdpHttpConfig;
import org.apache.polaris.extension.auth.common.config.ImmutableStaticTokenConfig;
import org.apache.polaris.extension.auth.common.config.PdpHttpConfig;
import org.junit.jupiter.api.Test;

public class AuthzenAuthorizationConfigTest {

  private static final PdpHttpConfig HTTP =
      ImmutablePdpHttpConfig.builder().timeout(Duration.ofSeconds(2)).verifySsl(true).build();

  private static ImmutableMappingConfig mapping() {
    return ImmutableMappingConfig.builder()
        .subjectType("user")
        .resourceIdFormat(AuthzenAuthorizationConfig.ResourceIdFormat.PATH)
        .resourceIdSeparator("/")
        .actionNameCase(AuthzenAuthorizationConfig.ActionNameCase.AS_IS)
        .rootResourceType("ROOT")
        .build();
  }

  private static ImmutableAuthzenAuthorizationConfig.Builder config() {
    return ImmutableAuthzenAuthorizationConfig.builder()
        .useBatchEndpoint(true)
        .mapping(mapping())
        .http(HTTP)
        .auth(
            ImmutableAuthenticationConfig.builder()
                .type(AuthzenAuthorizationConfig.AuthenticationType.NONE)
                .build());
  }

  @Test
  void requiresAPdpUriOrAnExplicitEvaluationEndpoint() {
    assertThatThrownBy(() -> config().build().validate())
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("pdp-uri")
        .hasMessageContaining("access-evaluation-endpoint");

    assertThatCode(() -> config().pdpUri(URI.create("https://pdp.example.com")).build().validate())
        .doesNotThrowAnyException();

    assertThatCode(
            () ->
                config()
                    .accessEvaluationEndpoint(URI.create("https://pdp.example.com/eval"))
                    .build()
                    .validate())
        .doesNotThrowAnyException();
  }

  @Test
  void rejectsNonHttpSchemes() {
    assertThatThrownBy(
            () -> config().pdpUri(URI.create("ftp://pdp.example.com")).build().validate())
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("must use http or https scheme");
  }

  @Test
  void bearerAuthenticationRequiresABearerConfiguration() {
    assertThatThrownBy(
            () ->
                config()
                    .pdpUri(URI.create("https://pdp.example.com"))
                    .auth(
                        ImmutableAuthenticationConfig.builder()
                            .type(AuthzenAuthorizationConfig.AuthenticationType.BEARER)
                            .build())
                    .build()
                    .validate())
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Bearer configuration is required");

    assertThatCode(
            () ->
                config()
                    .pdpUri(URI.create("https://pdp.example.com"))
                    .auth(
                        ImmutableAuthenticationConfig.builder()
                            .type(AuthzenAuthorizationConfig.AuthenticationType.BEARER)
                            .bearer(
                                ImmutableBearerTokenConfig.builder()
                                    .staticToken(
                                        ImmutableStaticTokenConfig.builder().value("token").build())
                                    .build())
                            .build())
                    .build()
                    .validate())
        .doesNotThrowAnyException();
  }

  @Test
  void clientCredentialsAuthenticationRequiresACompleteConfiguration() {
    assertThatThrownBy(
            () ->
                config()
                    .pdpUri(URI.create("https://pdp.example.com"))
                    .auth(
                        ImmutableAuthenticationConfig.builder()
                            .type(AuthzenAuthorizationConfig.AuthenticationType.CLIENT_CREDENTIALS)
                            .build())
                    .build()
                    .validate())
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Client credentials configuration is required");

    assertThatCode(
            () ->
                config()
                    .pdpUri(URI.create("https://pdp.example.com"))
                    .auth(
                        ImmutableAuthenticationConfig.builder()
                            .type(AuthzenAuthorizationConfig.AuthenticationType.CLIENT_CREDENTIALS)
                            .clientCredentials(
                                ImmutableClientCredentialsConfig.builder()
                                    .tokenEndpoint(URI.create("https://idp.example.com/token"))
                                    .clientId("polaris-pdp")
                                    .clientSecret("s3cr3t")
                                    .build())
                            .build())
                    .build()
                    .validate())
        .doesNotThrowAnyException();
  }

  @Test
  void clientCredentialsRejectsAnEmptyClientId() {
    assertThatThrownBy(
            () ->
                config()
                    .pdpUri(URI.create("https://pdp.example.com"))
                    .auth(
                        ImmutableAuthenticationConfig.builder()
                            .type(AuthzenAuthorizationConfig.AuthenticationType.CLIENT_CREDENTIALS)
                            .clientCredentials(
                                ImmutableClientCredentialsConfig.builder()
                                    .tokenEndpoint(URI.create("https://idp.example.com/token"))
                                    .clientId("")
                                    .clientSecret("s3cr3t")
                                    .build())
                            .build())
                    .build()
                    .validate())
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Client id cannot be null or empty");
  }
}
