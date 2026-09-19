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
package org.apache.polaris.extension.auth.common.config;

import static com.google.common.base.Preconditions.checkArgument;

import com.google.common.base.Strings;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Optional;
import org.apache.polaris.immutables.PolarisImmutable;

/**
 * Bearer token configuration shared by the external Policy Decision Point integrations.
 *
 * <p>Exactly one of {@link #staticToken()} or {@link #fileBased()} must be configured.
 */
@PolarisImmutable
public interface BearerTokenConfig {
  /** Static bearer token configuration */
  Optional<StaticTokenConfig> staticToken();

  /** File-based bearer token configuration */
  Optional<FileBasedConfig> fileBased();

  default void validate() {
    // Ensure exactly one bearer token configuration is present (mutually exclusive)
    checkArgument(
        staticToken().isPresent() ^ fileBased().isPresent(),
        "Exactly one of 'static-token' or 'file-based' bearer token configuration must be specified");

    // Validate the present configuration
    if (staticToken().isPresent()) {
      staticToken().get().validate();
    } else {
      fileBased().get().validate();
    }
  }

  /** Configuration for static bearer tokens */
  @PolarisImmutable
  interface StaticTokenConfig {
    /** Static bearer token value */
    String value();

    default void validate() {
      checkArgument(
          !Strings.isNullOrEmpty(value()), "Static bearer token value cannot be null or empty");
    }
  }

  /** Configuration for file-based bearer tokens */
  @PolarisImmutable
  interface FileBasedConfig {
    /** Path to file containing bearer token */
    Path path();

    /** How often to refresh file-based bearer tokens (defaults to 5 minutes if not specified) */
    Optional<Duration> refreshInterval();

    /**
     * Whether to automatically detect JWT tokens and use their 'exp' field for refresh timing. If
     * true and the token is a valid JWT with an 'exp' claim, the token will be refreshed based on
     * the expiration time minus the buffer, rather than the fixed refresh interval. Defaults to
     * true if not specified.
     */
    Optional<Boolean> jwtExpirationRefresh();

    /**
     * Buffer time before JWT expiration to refresh the token. Only used when jwtExpirationRefresh
     * is true and the token is a valid JWT. Defaults to 1 minute if not specified.
     */
    Optional<Duration> jwtExpirationBuffer();

    /**
     * How long to wait for the first token load before failing a request. Defaults to 5 seconds.
     */
    Optional<Duration> initialTokenWait();

    /** How long to wait before retrying after a failed token refresh. Defaults to 1 second. */
    Optional<Duration> refreshRetryInterval();

    default void validate() {
      checkArgument(
          refreshInterval().isEmpty() || refreshInterval().get().isPositive(),
          "refreshInterval must be positive");
      checkArgument(
          jwtExpirationBuffer().isEmpty() || jwtExpirationBuffer().get().isPositive(),
          "jwtExpirationBuffer must be positive");
      checkArgument(
          initialTokenWait().isEmpty() || initialTokenWait().get().isPositive(),
          "initialTokenWait must be positive");
      checkArgument(
          refreshRetryInterval().isEmpty() || refreshRetryInterval().get().isPositive(),
          "refreshRetryInterval must be positive");
    }
  }
}
