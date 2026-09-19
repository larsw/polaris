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

import java.time.Clock;
import java.time.Duration;
import org.apache.polaris.extension.auth.common.config.BearerTokenConfig;
import org.apache.polaris.nosql.async.AsyncExec;

/** Builds {@link BearerTokenProvider}s from {@link BearerTokenConfig}. */
public final class BearerTokenProviders {

  private BearerTokenProviders() {}

  /** Default refresh interval used when a file-based token does not configure one. */
  public static final Duration DEFAULT_REFRESH_INTERVAL = Duration.ofMinutes(5);

  /** Default buffer applied before a JWT's expiration when scheduling a refresh. */
  public static final Duration DEFAULT_JWT_EXPIRATION_BUFFER = Duration.ofMinutes(1);

  /** Default time a caller waits for the very first token to become available. */
  public static final Duration DEFAULT_INITIAL_TOKEN_WAIT = Duration.ofSeconds(5);

  /** Default delay before retrying a failed token refresh. */
  public static final Duration DEFAULT_REFRESH_RETRY_INTERVAL = Duration.ofSeconds(1);

  /**
   * Creates the bearer token provider described by the given configuration.
   *
   * @param config validated bearer token configuration
   * @param asyncExec executor used to schedule refreshes of file-based tokens
   * @param clock clock used for refresh scheduling
   * @return a provider for static or file-based tokens
   */
  public static BearerTokenProvider create(
      BearerTokenConfig config, AsyncExec asyncExec, Clock clock) {
    if (config.staticToken().isPresent()) {
      return new StaticBearerTokenProvider(config.staticToken().get().value());
    }
    if (config.fileBased().isPresent()) {
      BearerTokenConfig.FileBasedConfig fileConfig = config.fileBased().get();
      return new FileBearerTokenProvider(
          fileConfig.path(),
          fileConfig.refreshInterval().orElse(DEFAULT_REFRESH_INTERVAL),
          fileConfig.jwtExpirationRefresh().orElse(true),
          fileConfig.jwtExpirationBuffer().orElse(DEFAULT_JWT_EXPIRATION_BUFFER),
          fileConfig.initialTokenWait().orElse(DEFAULT_INITIAL_TOKEN_WAIT),
          fileConfig.refreshRetryInterval().orElse(DEFAULT_REFRESH_RETRY_INTERVAL),
          asyncExec,
          clock::instant);
    }
    throw new IllegalStateException(
        "No bearer token configuration found. Must specify either 'static-token' or 'file-based'");
  }
}
