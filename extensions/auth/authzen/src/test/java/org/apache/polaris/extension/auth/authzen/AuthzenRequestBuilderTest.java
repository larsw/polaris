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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.polaris.core.auth.AuthorizationIntent;
import org.apache.polaris.core.auth.PathSegment;
import org.apache.polaris.core.auth.PolarisAuthorizableOperation;
import org.apache.polaris.core.auth.PolarisPrincipal;
import org.apache.polaris.core.auth.PolarisSecurable;
import org.apache.polaris.core.auth.PrivilegeGrantAuthorizationIntent;
import org.apache.polaris.core.auth.RenameAuthorizationIntent;
import org.apache.polaris.core.auth.RootPrivilegeGrantAuthorizationIntent;
import org.apache.polaris.core.auth.SingleTargetAuthorizationIntent;
import org.apache.polaris.core.auth.TargetlessAuthorizationIntent;
import org.apache.polaris.core.entity.PolarisEntityType;
import org.junit.jupiter.api.Test;

/** Verifies the AuthZEN payload Polaris builds from its authorization intents. */
public class AuthzenRequestBuilderTest {

  private static final ObjectMapper MAPPER = JsonMapper.builder().build();

  private static final PolarisPrincipal ALICE =
      PolarisPrincipal.of("alice", Map.of("team", "ml"), Set.of("analyst"));

  private static final PolarisSecurable TABLE =
      PolarisSecurable.of(
          new PathSegment(PolarisEntityType.CATALOG, "prod_catalog"),
          new PathSegment(PolarisEntityType.NAMESPACE, "sales"),
          new PathSegment(PolarisEntityType.TABLE_LIKE, "orders"));

  private static final PolarisSecurable OTHER_TABLE =
      PolarisSecurable.of(
          new PathSegment(PolarisEntityType.CATALOG, "prod_catalog"),
          new PathSegment(PolarisEntityType.NAMESPACE, "sales"),
          new PathSegment(PolarisEntityType.TABLE_LIKE, "orders_v2"));

  private static final PolarisSecurable PRINCIPAL_SECURABLE =
      PolarisSecurable.of(new PathSegment(PolarisEntityType.PRINCIPAL, "bob"));

  /**
   * A builder pre-populated with the {@code @WithDefault} values of {@link
   * AuthzenAuthorizationConfig.MappingConfig}. SmallRye applies those defaults when it materialises
   * the config mapping; the generated immutable has no notion of them, so tests state them here.
   */
  private static ImmutableMappingConfig.Builder mappingBuilder() {
    return ImmutableMappingConfig.builder()
        .subjectType("user")
        .resourceIdFormat(AuthzenAuthorizationConfig.ResourceIdFormat.PATH)
        .resourceIdSeparator("/")
        .actionNameCase(AuthzenAuthorizationConfig.ActionNameCase.AS_IS)
        .rootResourceType("ROOT");
  }

  private static AuthzenAuthorizationConfig.MappingConfig defaults() {
    return mappingBuilder().build();
  }

  private static JsonNode json(Object value) {
    return MAPPER.valueToTree(value);
  }

  private static AuthzenRequestBuilder builder(AuthzenAuthorizationConfig.MappingConfig mapping) {
    return new AuthzenRequestBuilder(mapping, "prod-realm");
  }

  @Test
  void buildsSubjectFromPrincipal() {
    JsonNode subject = json(builder(defaults()).subject(ALICE));

    assertThat(subject.get("type").asText()).isEqualTo("user");
    assertThat(subject.get("id").asText()).isEqualTo("alice");
    assertThat(subject.get("properties").get("realm").asText()).isEqualTo("prod-realm");
    assertThat(subject.get("properties").get("roles").size()).isEqualTo(1);
    assertThat(subject.get("properties").get("roles").get(0).asText()).isEqualTo("analyst");
  }

  @Test
  void appliesSubjectIdPrefix() {
    AuthzenAuthorizationConfig.MappingConfig mapping =
        mappingBuilder().subjectIdPrefix("username:").build();

    assertThat(json(builder(mapping).subject(ALICE)).get("id").asText())
        .isEqualTo("username:alice");
  }

  @Test
  void omitsRolesWhenPrincipalHasNone() {
    PolarisPrincipal roleless = PolarisPrincipal.of("svc", Map.of(), Set.of());

    assertThat(json(builder(defaults()).subject(roleless)).get("properties").has("roles"))
        .isFalse();
  }

  @Test
  void buildsResourceFromSingleTargetIntent() throws Exception {
    AuthorizationIntent intent =
        new SingleTargetAuthorizationIntent(PolarisAuthorizableOperation.LOAD_TABLE, TABLE);

    JsonNode resource = json(builder(defaults()).resource(intent));

    assertThat(resource.get("type").asText()).isEqualTo("TABLE_LIKE");
    assertThat(resource.get("id").asText()).isEqualTo("prod_catalog/sales/orders");
    assertThat(resource.get("properties").get("name").asText()).isEqualTo("orders");
    assertThat(resource.get("properties").get("parents"))
        .isEqualTo(
            MAPPER.readTree(
                """
                [
                  {"type": "CATALOG", "name": "prod_catalog"},
                  {"type": "NAMESPACE", "name": "sales"}
                ]
                """));
    assertThat(resource.get("properties").has("secondaries")).isFalse();
  }

  @Test
  void targetlessIntentUsesRealmScopedResource() {
    AuthorizationIntent intent =
        new TargetlessAuthorizationIntent(PolarisAuthorizableOperation.LIST_CATALOGS);

    JsonNode resource = json(builder(defaults()).resource(intent));

    assertThat(resource.get("type").asText()).isEqualTo("ROOT");
    assertThat(resource.get("id").asText()).isEqualTo("prod-realm");
    assertThat(resource.get("properties").get("name").asText()).isEqualTo("prod-realm");
    assertThat(resource.get("properties").has("parents")).isFalse();
  }

  @Test
  void renameIntentCarriesDestinationAsSecondary() {
    AuthorizationIntent intent =
        new RenameAuthorizationIntent(
            PolarisAuthorizableOperation.RENAME_TABLE, TABLE, OTHER_TABLE);

    JsonNode resource = json(builder(defaults()).resource(intent));

    assertThat(resource.get("id").asText()).isEqualTo("prod_catalog/sales/orders");
    JsonNode secondaries = resource.get("properties").get("secondaries");
    assertThat(secondaries.size()).isEqualTo(1);
    assertThat(secondaries.get(0).get("name").asText()).isEqualTo("orders_v2");
    assertThat(secondaries.get(0).get("type").asText()).isEqualTo("TABLE_LIKE");
    assertThat(secondaries.get(0).get("parents").size()).isEqualTo(2);
  }

  @Test
  void privilegeGrantIntentCarriesGranteeAsSecondary() {
    AuthorizationIntent intent =
        new PrivilegeGrantAuthorizationIntent(
            PolarisAuthorizableOperation.ADD_TABLE_GRANT_TO_CATALOG_ROLE,
            TABLE,
            PRINCIPAL_SECURABLE);

    JsonNode resource = json(builder(defaults()).resource(intent));

    assertThat(resource.get("type").asText()).isEqualTo("TABLE_LIKE");
    assertThat(resource.get("properties").get("secondaries").get(0).get("name").asText())
        .isEqualTo("bob");
  }

  @Test
  void rootPrivilegeGrantIntentIsRealmScopedWithSecondary() {
    AuthorizationIntent intent =
        new RootPrivilegeGrantAuthorizationIntent(
            PolarisAuthorizableOperation.ASSIGN_PRINCIPAL_ROLE, PRINCIPAL_SECURABLE);

    JsonNode resource = json(builder(defaults()).resource(intent));

    assertThat(resource.get("type").asText()).isEqualTo("ROOT");
    assertThat(resource.get("properties").get("secondaries").get(0).get("name").asText())
        .isEqualTo("bob");
  }

  @Test
  void resourceIdFormatNameUsesLeafName() {
    AuthzenAuthorizationConfig.MappingConfig mapping =
        mappingBuilder().resourceIdFormat(AuthzenAuthorizationConfig.ResourceIdFormat.NAME).build();
    AuthorizationIntent intent =
        new SingleTargetAuthorizationIntent(PolarisAuthorizableOperation.LOAD_TABLE, TABLE);

    assertThat(json(builder(mapping).resource(intent)).get("id").asText()).isEqualTo("orders");
  }

  @Test
  void resourceIdFormatTypeKeepsIdWithinTheFiniteSetOfEntityTypes() {
    AuthzenAuthorizationConfig.MappingConfig mapping =
        mappingBuilder()
            .resourceIdFormat(AuthzenAuthorizationConfig.ResourceIdFormat.TYPE)
            .resourceTypePrefix("polaris:")
            .build();

    JsonNode table =
        json(
            builder(mapping)
                .resource(
                    new SingleTargetAuthorizationIntent(
                        PolarisAuthorizableOperation.LOAD_TABLE, TABLE)));
    assertThat(table.get("type").asText()).isEqualTo("polaris:TABLE_LIKE");
    assertThat(table.get("id").asText()).isEqualTo("TABLE_LIKE");
    // the instance is still described, just not in the id
    assertThat(table.get("properties").get("name").asText()).isEqualTo("orders");

    JsonNode root =
        json(
            builder(mapping)
                .resource(
                    new TargetlessAuthorizationIntent(PolarisAuthorizableOperation.LIST_CATALOGS)));
    assertThat(root.get("type").asText()).isEqualTo("polaris:ROOT");
    assertThat(root.get("id").asText()).isEqualTo("ROOT");
  }

  @Test
  void resourceIdSeparatorIsConfigurable() {
    AuthzenAuthorizationConfig.MappingConfig mapping =
        mappingBuilder().resourceIdSeparator("\u001f").build();
    AuthorizationIntent intent =
        new SingleTargetAuthorizationIntent(PolarisAuthorizableOperation.LOAD_TABLE, TABLE);

    assertThat(json(builder(mapping).resource(intent)).get("id").asText())
        .isEqualTo("prod_catalog\u001fsales\u001forders");
  }

  @Test
  void actionNameCaseIsConfigurable() {
    AuthorizationIntent intent =
        new TargetlessAuthorizationIntent(PolarisAuthorizableOperation.LIST_CATALOGS);

    assertThat(json(builder(defaults()).action(intent)).get("name").asText())
        .isEqualTo("LIST_CATALOGS");

    AuthzenAuthorizationConfig.MappingConfig lower =
        mappingBuilder().actionNameCase(AuthzenAuthorizationConfig.ActionNameCase.LOWER).build();
    assertThat(json(builder(lower).action(intent)).get("name").asText()).isEqualTo("list_catalogs");
  }

  @Test
  void batchRequestCarriesSubjectAndContextOnceAndDenyOnFirstDeny() {
    List<AuthorizationIntent> intents =
        List.of(
            new SingleTargetAuthorizationIntent(PolarisAuthorizableOperation.UPDATE_TABLE, TABLE),
            new SingleTargetAuthorizationIntent(
                PolarisAuthorizableOperation.UPDATE_TABLE, OTHER_TABLE));

    JsonNode request = json(builder(defaults()).evaluationsRequest(ALICE, "req-1", intents));

    assertThat(request.get("subject").get("id").asText()).isEqualTo("alice");
    assertThat(request.get("context").get("request_id").asText()).isEqualTo("req-1");
    assertThat(request.get("context").get("realm").asText()).isEqualTo("prod-realm");
    assertThat(request.get("options").get("evaluations_semantic").asText())
        .isEqualTo("deny_on_first_deny");

    JsonNode evaluations = request.get("evaluations");
    assertThat(evaluations.size()).isEqualTo(2);
    // entries carry only action and resource; the subject is shared
    assertThat(evaluations.get(0).has("subject")).isFalse();
    assertThat(evaluations.get(0).get("action").get("name").asText()).isEqualTo("UPDATE_TABLE");
    assertThat(evaluations.get(0).get("resource").get("id").asText())
        .isEqualTo("prod_catalog/sales/orders");
    assertThat(evaluations.get(1).get("resource").get("id").asText())
        .isEqualTo("prod_catalog/sales/orders_v2");
  }

  @Test
  void singleEvaluationRequestHasSubjectActionResourceAndContext() {
    AuthorizationIntent intent =
        new SingleTargetAuthorizationIntent(PolarisAuthorizableOperation.LOAD_TABLE, TABLE);

    JsonNode request = json(builder(defaults()).evaluationRequest(ALICE, "req-2", intent));

    assertThat(request.size()).isEqualTo(4);
    assertThat(request.has("subject")).isTrue();
    assertThat(request.has("action")).isTrue();
    assertThat(request.has("resource")).isTrue();
    assertThat(request.has("context")).isTrue();
    assertThat(request.get("action").get("name").asText()).isEqualTo("LOAD_TABLE");
  }
}
