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

import java.util.List;
import java.util.UUID;
import org.apache.polaris.core.auth.AuthorizationDecision;
import org.apache.polaris.core.auth.AuthorizationIntent;
import org.apache.polaris.core.auth.AuthorizationRequest;
import org.apache.polaris.core.auth.AuthorizationState;
import org.apache.polaris.core.auth.PolarisAuthorizer;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link PolarisAuthorizer} that delegates decisions to a Policy Decision Point speaking the OpenID
 * AuthZEN Authorization API 1.0.
 *
 * <p>Unlike the OPA integration, which speaks OPA's own data-query API, this authorizer targets a
 * vendor-neutral protocol: any conforming PDP -- Keycloak, Cerbos, Topaz and others -- can be used
 * without Polaris knowing which policy engine is behind it.
 *
 * <p>Like every external-PDP authorizer, this bypasses Polaris's built-in role-based authorization.
 * Principal roles and catalog roles are passed to the PDP as subject properties, but no Polaris
 * grant is consulted: the PDP decides.
 *
 * <p><strong>Preview Feature:</strong> this implementation is a preview feature and is not a stable
 * release. It may undergo breaking changes in future versions. Use with caution in production
 * environments.
 */
class AuthzenPolarisAuthorizer implements PolarisAuthorizer {

  private static final Logger LOGGER = LoggerFactory.getLogger(AuthzenPolarisAuthorizer.class);

  private static final String DENIED_MESSAGE = "AuthZEN PDP denied authorization";

  private final AuthzenPdpClient pdpClient;
  private final AuthzenRequestBuilder requestBuilder;
  private final @Nullable String requestId;
  private final String realm;

  AuthzenPolarisAuthorizer(
      @NonNull AuthzenPdpClient pdpClient,
      @NonNull AuthzenRequestBuilder requestBuilder,
      @Nullable String requestId,
      @NonNull String realm) {
    this.pdpClient = pdpClient;
    this.requestBuilder = requestBuilder;
    this.requestId = requestId;
    this.realm = realm;
  }

  /**
   * Resolves authorization inputs using {@code resolveAll()}.
   *
   * <p>This scope is intentionally broad, matching the OPA authorizer: callers read resolved paths
   * back out of the manifest after authorization, so a narrower resolution would break them.
   */
  @Override
  public void resolveAuthorizationInputs(
      @NonNull AuthorizationState authzState, @NonNull AuthorizationRequest request) {
    authzState.getResolutionManifest().resolveAll();
  }

  @Override
  @NonNull
  public AuthorizationDecision authorize(
      @NonNull AuthorizationState authzState, @NonNull AuthorizationRequest request) {
    List<AuthorizationIntent> intents = request.intents();
    String effectiveRequestId = requestId != null ? requestId : UUID.randomUUID().toString();

    if (intents.size() > 1 && pdpClient.batchEnabled()) {
      return authorizeBatched(request, intents, effectiveRequestId);
    }
    return authorizeOneByOne(request, intents, effectiveRequestId);
  }

  private AuthorizationDecision authorizeOneByOne(
      AuthorizationRequest request, List<AuthorizationIntent> intents, String effectiveRequestId) {
    for (AuthorizationIntent intent : intents) {
      boolean allowed =
          pdpClient.evaluate(
              requestBuilder.evaluationRequest(request.principal(), effectiveRequestId, intent),
              effectiveRequestId);
      if (!allowed) {
        logDenial(request, intent, effectiveRequestId);
        return AuthorizationDecision.deny(DENIED_MESSAGE);
      }
    }
    return AuthorizationDecision.allow();
  }

  /**
   * Evaluates every intent in one round-trip.
   *
   * <p>Because Polaris asks for {@code deny_on_first_deny} semantics, the PDP may legitimately
   * return fewer decisions than it was sent -- but only by stopping at a deny. Any other shortfall
   * means intents went unevaluated, which is treated as a denial rather than assumed to be a
   * permit.
   */
  private AuthorizationDecision authorizeBatched(
      AuthorizationRequest request, List<AuthorizationIntent> intents, String effectiveRequestId) {
    List<Boolean> decisions =
        pdpClient.evaluations(
            requestBuilder.evaluationsRequest(request.principal(), effectiveRequestId, intents),
            effectiveRequestId);

    if (decisions.isEmpty()) {
      LOGGER.warn(
          "AuthZEN PDP returned no decisions for {} intents, denying; realm={} requestId={}",
          intents.size(),
          realm,
          effectiveRequestId);
      return AuthorizationDecision.deny(DENIED_MESSAGE);
    }
    if (decisions.size() > intents.size()) {
      LOGGER.warn(
          "AuthZEN PDP returned {} decisions for {} intents, denying; realm={} requestId={}",
          decisions.size(),
          intents.size(),
          realm,
          effectiveRequestId);
      return AuthorizationDecision.deny(DENIED_MESSAGE);
    }

    for (int i = 0; i < decisions.size(); i++) {
      if (!decisions.get(i)) {
        logDenial(request, intents.get(i), effectiveRequestId);
        return AuthorizationDecision.deny(DENIED_MESSAGE);
      }
    }

    if (decisions.size() < intents.size()) {
      LOGGER.warn(
          "AuthZEN PDP returned {} permits for {} intents without a deny, denying the unevaluated remainder; realm={} requestId={}",
          decisions.size(),
          intents.size(),
          realm,
          effectiveRequestId);
      return AuthorizationDecision.deny(DENIED_MESSAGE);
    }

    return AuthorizationDecision.allow();
  }

  private void logDenial(
      AuthorizationRequest request, AuthorizationIntent intent, String effectiveRequestId) {
    LOGGER.debug(
        "AuthZEN PDP denied authorization for principal={} operation={} intent={} realm={} requestId={}",
        request.principal().getName(),
        intent.operation(),
        intent,
        realm,
        effectiveRequestId);
  }
}
