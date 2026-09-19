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
package org.apache.polaris.extension.auth.opa;

import static com.google.common.base.Preconditions.checkArgument;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;
import java.net.URI;
import java.util.Optional;
import org.apache.polaris.extension.auth.common.config.BearerTokenConfig;
import org.apache.polaris.extension.auth.common.config.PdpHttpConfig;
import org.apache.polaris.immutables.PolarisImmutable;

/**
 * Configuration for OPA (Open Policy Agent) authorization.
 *
 * <p><strong>Beta Feature:</strong> OPA authorization is currently in Beta and is not a stable
 * release. It may undergo breaking changes in future versions. Use with caution in production
 * environments.
 */
@PolarisImmutable
@ConfigMapping(prefix = "polaris.authorization.opa")
public interface OpaAuthorizationConfig {

  /** Authentication types supported by OPA authorization */
  enum AuthenticationType {
    NONE("none"),
    BEARER("bearer");

    private final String value;

    AuthenticationType(String value) {
      this.value = value;
    }

    public String getValue() {
      return value;
    }
  }

  Optional<URI> policyUri();

  AuthenticationConfig auth();

  PdpHttpConfig http();

  /** Validates the complete OPA configuration */
  default void validate() {
    checkArgument(
        policyUri().isPresent(), "polaris.authorization.opa.policy-uri must be configured");

    URI uri = policyUri().get();
    String scheme = uri.getScheme();
    checkArgument(
        "http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme),
        "polaris.authorization.opa.policy-uri must use http or https scheme, but got: " + scheme);

    auth().validate();
  }

  /** Authentication configuration for OPA communication. */
  @PolarisImmutable
  interface AuthenticationConfig {
    /** Type of authentication */
    @WithDefault("none")
    AuthenticationType type();

    /** Bearer token authentication configuration */
    Optional<BearerTokenConfig> bearer();

    default void validate() {
      switch (type()) {
        case BEARER:
          checkArgument(
              bearer().isPresent(), "Bearer configuration is required when type is 'bearer'");
          bearer().get().validate();
          break;
        case NONE:
          // No authentication - nothing to validate
          break;
        default:
          throw new IllegalArgumentException(
              "Invalid authentication type: " + type() + ". Supported types: 'bearer', 'none'");
      }
    }
  }
}
