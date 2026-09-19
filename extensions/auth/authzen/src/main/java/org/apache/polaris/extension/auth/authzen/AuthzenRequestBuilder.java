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

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;
import org.apache.polaris.core.auth.AuthorizationIntent;
import org.apache.polaris.core.auth.PathSegment;
import org.apache.polaris.core.auth.PolarisPrincipal;
import org.apache.polaris.core.auth.PolarisSecurable;
import org.apache.polaris.core.auth.PolicyAttachmentAuthorizationIntent;
import org.apache.polaris.core.auth.PrivilegeGrantAuthorizationIntent;
import org.apache.polaris.core.auth.RenameAuthorizationIntent;
import org.apache.polaris.core.auth.RoleAssignmentAuthorizationIntent;
import org.apache.polaris.core.auth.RootPrivilegeGrantAuthorizationIntent;
import org.apache.polaris.core.auth.SingleTargetAuthorizationIntent;
import org.apache.polaris.core.auth.TargetlessAuthorizationIntent;
import org.apache.polaris.extension.auth.authzen.model.AuthzenAction;
import org.apache.polaris.extension.auth.authzen.model.AuthzenContext;
import org.apache.polaris.extension.auth.authzen.model.AuthzenEvaluationItem;
import org.apache.polaris.extension.auth.authzen.model.AuthzenEvaluationRequest;
import org.apache.polaris.extension.auth.authzen.model.AuthzenEvaluationsRequest;
import org.apache.polaris.extension.auth.authzen.model.AuthzenResource;
import org.apache.polaris.extension.auth.authzen.model.AuthzenResourceEntity;
import org.apache.polaris.extension.auth.authzen.model.AuthzenResourceProperties;
import org.apache.polaris.extension.auth.authzen.model.AuthzenSubject;
import org.apache.polaris.extension.auth.authzen.model.AuthzenSubjectProperties;
import org.apache.polaris.extension.auth.authzen.model.ImmutableAuthzenAction;
import org.apache.polaris.extension.auth.authzen.model.ImmutableAuthzenContext;
import org.apache.polaris.extension.auth.authzen.model.ImmutableAuthzenEvaluationItem;
import org.apache.polaris.extension.auth.authzen.model.ImmutableAuthzenEvaluationRequest;
import org.apache.polaris.extension.auth.authzen.model.ImmutableAuthzenEvaluationsOptions;
import org.apache.polaris.extension.auth.authzen.model.ImmutableAuthzenEvaluationsRequest;
import org.apache.polaris.extension.auth.authzen.model.ImmutableAuthzenResource;
import org.apache.polaris.extension.auth.authzen.model.ImmutableAuthzenResourceEntity;
import org.apache.polaris.extension.auth.authzen.model.ImmutableAuthzenResourceProperties;
import org.apache.polaris.extension.auth.authzen.model.ImmutableAuthzenSubject;
import org.apache.polaris.extension.auth.authzen.model.ImmutableAuthzenSubjectProperties;
import org.jspecify.annotations.Nullable;

/**
 * Translates Polaris authorization intents into AuthZEN request payloads.
 *
 * <p>AuthZEN evaluates exactly one {@code subject}/{@code action}/{@code resource} triple at a
 * time, while a Polaris intent may name a second resource and may name none at all. Two conventions
 * bridge the gap, and both are part of the documented contract with policy authors:
 *
 * <ul>
 *   <li>An intent with no target -- {@code LIST_CATALOGS} and friends -- is sent against a
 *       synthetic realm-scoped resource whose type is configurable and whose id is the realm
 *       identifier.
 *   <li>The secondary resource of a two-sided intent -- the destination of a rename, the grantee of
 *       a grant, the entity a policy attaches to -- is carried in {@code
 *       resource.properties.secondaries} rather than being dropped or split into a second
 *       evaluation.
 * </ul>
 */
class AuthzenRequestBuilder {

  /**
   * Asks the PDP to stop evaluating at the first deny. Polaris AND-combines intents, so later
   * decisions cannot change the outcome once one intent is denied.
   */
  static final String DENY_ON_FIRST_DENY = "deny_on_first_deny";

  private final AuthzenAuthorizationConfig.MappingConfig mapping;
  private final String realm;

  AuthzenRequestBuilder(AuthzenAuthorizationConfig.MappingConfig mapping, String realm) {
    this.mapping = mapping;
    this.realm = realm;
  }

  /** Builds a single Access Evaluation request for one intent. */
  AuthzenEvaluationRequest evaluationRequest(
      PolarisPrincipal principal, String requestId, AuthorizationIntent intent) {
    return ImmutableAuthzenEvaluationRequest.builder()
        .subject(subject(principal))
        .action(action(intent))
        .resource(resource(intent))
        .context(context(requestId))
        .build();
  }

  /** Builds a batched Access Evaluations request, one entry per intent, in order. */
  AuthzenEvaluationsRequest evaluationsRequest(
      PolarisPrincipal principal, String requestId, List<AuthorizationIntent> intents) {
    List<AuthzenEvaluationItem> items =
        intents.stream()
            .map(
                intent ->
                    (AuthzenEvaluationItem)
                        ImmutableAuthzenEvaluationItem.builder()
                            .action(action(intent))
                            .resource(resource(intent))
                            .build())
            .collect(Collectors.toList());

    return ImmutableAuthzenEvaluationsRequest.builder()
        .subject(subject(principal))
        .context(context(requestId))
        .options(
            ImmutableAuthzenEvaluationsOptions.builder()
                .evaluationsSemantic(DENY_ON_FIRST_DENY)
                .build())
        .evaluations(items)
        .build();
  }

  AuthzenSubject subject(PolarisPrincipal principal) {
    AuthzenSubjectProperties properties =
        ImmutableAuthzenSubjectProperties.builder()
            .addAllRoles(principal.getRoles())
            .realm(realm)
            .build();
    return ImmutableAuthzenSubject.builder()
        .type(mapping.subjectType())
        .id(mapping.subjectIdPrefix().orElse("") + principal.getName())
        .properties(properties)
        .build();
  }

  AuthzenContext context(String requestId) {
    return ImmutableAuthzenContext.builder().requestId(requestId).realm(realm).build();
  }

  AuthzenAction action(AuthorizationIntent intent) {
    String name = intent.operation().name();
    if (mapping.actionNameCase() == AuthzenAuthorizationConfig.ActionNameCase.LOWER) {
      name = name.toLowerCase(Locale.ROOT);
    }
    return ImmutableAuthzenAction.builder().name(name).build();
  }

  AuthzenResource resource(AuthorizationIntent intent) {
    Securables securables = securables(intent);
    List<AuthzenResourceEntity> secondaries =
        securables.secondary() == null
            ? List.of()
            : List.of(resourceEntity(securables.secondary()));

    if (securables.target() == null) {
      // Realm-scoped operation: there is no Polaris entity to name, so the realm stands in for it.
      return ImmutableAuthzenResource.builder()
          .type(withResourceTypePrefix(mapping.rootResourceType()))
          .id(rootResourceId())
          .properties(
              ImmutableAuthzenResourceProperties.builder()
                  .name(realm)
                  .secondaries(secondaries)
                  .build())
          .build();
    }

    PolarisSecurable target = securables.target();
    PathSegment leaf = target.getLeaf();
    AuthzenResourceProperties properties =
        ImmutableAuthzenResourceProperties.builder()
            .name(leaf.name())
            .parents(resourceEntities(target.getParents()))
            .secondaries(secondaries)
            .build();

    return ImmutableAuthzenResource.builder()
        .type(withResourceTypePrefix(leaf.entityType().name()))
        .id(resourceId(target))
        .properties(properties)
        .build();
  }

  private String withResourceTypePrefix(String type) {
    return mapping.resourceTypePrefix().orElse("") + type;
  }

  private String resourceId(PolarisSecurable securable) {
    return switch (mapping.resourceIdFormat()) {
      case NAME -> securable.getLeaf().name();
      case TYPE -> securable.getLeaf().entityType().name();
      case PATH ->
          securable.getPathSegments().stream()
              .map(PathSegment::name)
              .collect(Collectors.joining(mapping.resourceIdSeparator()));
    };
  }

  /**
   * The id of the synthetic realm-scoped resource.
   *
   * <p>With {@code resource-id-format=type} the id has to stay within the finite set of types a PDP
   * can register, so the configured root type is used instead of the realm identifier.
   */
  private String rootResourceId() {
    return mapping.resourceIdFormat() == AuthzenAuthorizationConfig.ResourceIdFormat.TYPE
        ? mapping.rootResourceType()
        : realm;
  }

  private AuthzenResourceEntity resourceEntity(PolarisSecurable securable) {
    return ImmutableAuthzenResourceEntity.builder()
        .type(securable.getLeaf().entityType().name())
        .name(securable.getLeaf().name())
        .parents(resourceEntities(securable.getParents()))
        .build();
  }

  private List<AuthzenResourceEntity> resourceEntities(List<PathSegment> segments) {
    List<AuthzenResourceEntity> entities = new ArrayList<>(segments.size());
    for (PathSegment segment : segments) {
      entities.add(
          ImmutableAuthzenResourceEntity.builder()
              .type(segment.entityType().name())
              .name(segment.name())
              .build());
    }
    return entities;
  }

  /**
   * Splits an intent into the resource it primarily acts on and, where the intent has one, the
   * second resource it relates to.
   */
  private static Securables securables(AuthorizationIntent intent) {
    return switch (intent) {
      case TargetlessAuthorizationIntent ignored -> new Securables(null, null);
      case SingleTargetAuthorizationIntent i -> new Securables(i.target(), null);
      case RenameAuthorizationIntent i -> new Securables(i.from(), i.to());
      case PolicyAttachmentAuthorizationIntent i -> new Securables(i.policy(), i.attachedTo());
      case RoleAssignmentAuthorizationIntent i -> new Securables(i.role(), i.assignee());
      case PrivilegeGrantAuthorizationIntent i -> new Securables(i.grantTarget(), i.grantee());
      case RootPrivilegeGrantAuthorizationIntent i -> new Securables(null, i.grantee());
    };
  }

  private record Securables(
      @Nullable PolarisSecurable target, @Nullable PolarisSecurable secondary) {}
}
