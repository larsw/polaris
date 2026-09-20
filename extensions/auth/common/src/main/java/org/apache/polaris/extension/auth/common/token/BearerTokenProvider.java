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

import org.jspecify.annotations.Nullable;

/**
 * Interface for providing bearer tokens for authentication.
 *
 * <p>Implementations can provide tokens from various sources such as:
 *
 * <ul>
 *   <li>Static string values
 *   <li>Files (with automatic reloading)
 *   <li>External token services
 * </ul>
 */
public interface BearerTokenProvider extends AutoCloseable {

  /**
   * Get the current bearer token.
   *
   * @return the bearer token, or null if no token is available
   */
  @Nullable String getToken();

  /**
   * Discards the current token because its consumer was told it is not acceptable, and obtains a
   * replacement.
   *
   * <p>A scheduled refresh only knows when a token is due to <em>expire</em>. It cannot know that a
   * token stopped being valid early -- because the issuer's signing keys were rotated, or the
   * client's session was revoked -- and until something says so, every request keeps presenting the
   * same rejected credential. This is how the consumer says so.
   *
   * <p>Implementations must tolerate being called concurrently and often: a rejection is typically
   * observed by every in-flight request at once, and a credential that is simply wrong would
   * otherwise become an unbounded stream of token requests.
   *
   * <p>The default does nothing, which is correct for a provider whose token cannot go stale
   * without its own refresh noticing -- a static one, say.
   */
  default void invalidate() {}

  /**
   * Clean up any resources used by this token provider. Should be called when the provider is no
   * longer needed.
   */
  @Override
  default void close() {
    // Default implementation does nothing
  }
}
