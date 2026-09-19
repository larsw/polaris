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
package org.apache.polaris.extension.auth.authzen.test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.polaris.core.auth.PolarisAuthorizableOperation;
import org.apache.polaris.core.entity.PolarisEntityType;
import org.apache.polaris.server.test.runner.spi.PolarisServerStartupAction;
import org.apache.polaris.server.test.runner.spi.PolarisServerStartupContext;
import org.apache.polaris.test.keycloak.KeycloakContainer;

/**
 * Starts a Keycloak server acting as an AuthZEN Policy Decision Point, before the Polaris server
 * process starts.
 *
 * <h2>Why the realm is shaped this way</h2>
 *
 * <p>Keycloak resolves {@code resource.id} against authorization-services resources that were
 * registered up front, and denies anything it cannot find. Catalogs, namespaces and tables are
 * created by the tests at runtime, so their names can never be registered in advance. Polaris is
 * therefore configured with {@code resource-id-format=type}, which keeps the id within the finite
 * set of Polaris entity types -- one registered Keycloak resource each.
 *
 * <p>Subjects are Polaris principal names looked up as Keycloak usernames. A Polaris principal that
 * has no Keycloak user is denied, which is what makes the "stranger" case work without any
 * configuration.
 */
public class AuthzenStartupAction implements PolarisServerStartupAction {

  /** The Polaris principal permitted to perform every operation. */
  private static final String OPERATOR_PRINCIPAL = "root";

  /** The Polaris principal permitted to perform read-only operations only. */
  private static final String READER_PRINCIPAL = "analyst";

  private static final String CLIENT_ID = "polaris-pdp";
  private static final String CLIENT_SECRET = "polaris-pdp-secret";
  private static final String RESOURCE_TYPE_PREFIX = "polaris:";

  private static final String OPERATOR_POLICY = "polaris-operator-policy";
  private static final String READER_POLICY = "polaris-reader-policy";

  /** Operations the read-only principal is allowed to perform. */
  private static final Set<PolarisAuthorizableOperation> READ_ONLY_OPERATIONS =
      Set.of(
          PolarisAuthorizableOperation.LIST_CATALOGS,
          PolarisAuthorizableOperation.GET_CATALOG,
          PolarisAuthorizableOperation.LIST_NAMESPACES,
          PolarisAuthorizableOperation.LOAD_NAMESPACE_METADATA,
          PolarisAuthorizableOperation.NAMESPACE_EXISTS,
          PolarisAuthorizableOperation.LIST_TABLES,
          PolarisAuthorizableOperation.LOAD_TABLE,
          PolarisAuthorizableOperation.TABLE_EXISTS,
          PolarisAuthorizableOperation.LIST_VIEWS,
          PolarisAuthorizableOperation.LOAD_VIEW,
          PolarisAuthorizableOperation.VIEW_EXISTS);

  private static final ObjectMapper MAPPER = JsonMapper.builder().build();

  private KeycloakContainer keycloak;
  private HttpClient httpClient;

  @Override
  @SuppressWarnings("resource")
  public void start(PolarisServerStartupContext context) {
    keycloak = new KeycloakContainer().withFeatures("authzen");
    keycloak.start();
    httpClient = HttpClient.newHttpClient();

    keycloak.createUser(OPERATOR_PRINCIPAL, "s3cr3t");
    keycloak.createUser(READER_PRINCIPAL, "s3cr3t");

    String clientUuid = createPdpClient();
    useAffirmativeDecisionStrategy(clientUuid);
    createScopes(clientUuid);
    createResources(clientUuid);
    createUserPolicy(clientUuid, OPERATOR_POLICY, OPERATOR_PRINCIPAL);
    createUserPolicy(clientUuid, READER_POLICY, READER_PRINCIPAL);
    createScopePermission(
        clientUuid, "polaris-operator-permission", allOperationNames(), OPERATOR_POLICY);
    createScopePermission(
        clientUuid, "polaris-reader-permission", readOnlyOperationNames(), READER_POLICY);

    verifyRealm();
    configurePolaris(context);
  }

  /**
   * Asks the PDP the question the first test will provoke, before Polaris starts.
   *
   * <p>Without this, a realm that was configured wrongly is indistinguishable from a Polaris
   * payload that does not match what Keycloak expects: both simply deny.
   */
  private void verifyRealm() {
    String evaluationEndpoint =
        keycloak.getBaseUrl() + "/realms/" + keycloak.getRealm() + "/authzen/access/v1/evaluation";
    String body =
        """
        {
          "subject": {"type": "user", "id": "username:%s"},
          "resource": {"type": "%sROOT", "id": "ROOT"},
          "action": {"name": "%s"}
        }"""
            .formatted(
                OPERATOR_PRINCIPAL,
                RESOURCE_TYPE_PREFIX,
                PolarisAuthorizableOperation.LIST_CATALOGS.name());

    HttpRequest request =
        HttpRequest.newBuilder()
            .uri(URI.create(evaluationEndpoint))
            .header("Authorization", "Bearer " + pdpAccessToken())
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build();
    HttpResponse<String> response = send(request);
    if (response.statusCode() != 200 || !response.body().contains("\"decision\":true")) {
      throw new IllegalStateException(
          "The AuthZEN test realm does not permit "
              + OPERATOR_PRINCIPAL
              + " to "
              + PolarisAuthorizableOperation.LIST_CATALOGS
              + ". PDP answered HTTP "
              + response.statusCode()
              + ": "
              + response.body());
    }
  }

  /** An access token for the PDP client, obtained the same way Polaris obtains one. */
  private String pdpAccessToken() {
    HttpRequest request =
        HttpRequest.newBuilder()
            .uri(
                URI.create(
                    keycloak.getBaseUrl()
                        + "/realms/"
                        + keycloak.getRealm()
                        + "/protocol/openid-connect/token"))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(
                HttpRequest.BodyPublishers.ofString(
                    "grant_type=client_credentials&client_id="
                        + CLIENT_ID
                        + "&client_secret="
                        + CLIENT_SECRET))
            .build();
    HttpResponse<String> response = send(request);
    if (response.statusCode() != 200) {
      throw new IllegalStateException(
          "Could not obtain a PDP client token: HTTP " + response.statusCode());
    }
    try {
      return MAPPER.readTree(response.body()).get("access_token").asText();
    } catch (Exception e) {
      throw new IllegalStateException("Could not parse the PDP client token response", e);
    }
  }

  @Override
  public void close() {
    if (keycloak != null) {
      keycloak.stop();
      keycloak = null;
    }
    httpClient = null;
  }

  private void configurePolaris(PolarisServerStartupContext context) {
    String realmUri = keycloak.getBaseUrl() + "/realms/" + keycloak.getRealm();
    Map<String, String> props = context.getSystemProperties();
    props.put("polaris.authorization.authzen.pdp-uri", realmUri);
    props.put("polaris.authorization.authzen.auth.type", "client-credentials");
    props.put(
        "polaris.authorization.authzen.auth.client-credentials.token-endpoint",
        realmUri + "/protocol/openid-connect/token");
    props.put("polaris.authorization.authzen.auth.client-credentials.client-id", CLIENT_ID);
    props.put("polaris.authorization.authzen.auth.client-credentials.client-secret", CLIENT_SECRET);
    // Keycloak resolves users by username only when the id says so explicitly.
    props.put("polaris.authorization.authzen.mapping.subject-id-prefix", "username:");
    props.put("polaris.authorization.authzen.mapping.resource-type-prefix", RESOURCE_TYPE_PREFIX);
    props.put("polaris.authorization.authzen.mapping.resource-id-format", "type");
  }

  private String createPdpClient() {
    Map<String, Object> client = new LinkedHashMap<>();
    client.put("clientId", CLIENT_ID);
    client.put("enabled", true);
    client.put("secret", CLIENT_SECRET);
    client.put("publicClient", false);
    client.put("serviceAccountsEnabled", true);
    client.put("directAccessGrantsEnabled", false);
    client.put("authorizationServicesEnabled", true);
    adminPost("/clients", client);

    JsonNode clients = adminGet("/clients?clientId=" + CLIENT_ID);
    if (clients.isEmpty()) {
      throw new IllegalStateException("Keycloak client " + CLIENT_ID + " was not created");
    }
    return clients.get(0).get("id").asText();
  }

  /**
   * Switches the resource server to {@code AFFIRMATIVE}, so that access is granted when
   * <em>any</em> permission grants it.
   *
   * <p>Keycloak defaults a resource server to {@code UNANIMOUS}, which requires every permission
   * that covers a (resource, scope) pair to grant. With one permission per role that is never true:
   * the operator permission grants the operator and the reader permission denies them, so everyone
   * is denied. This is the single most confusing part of modelling role-based access in Keycloak
   * authorization services.
   */
  private void useAffirmativeDecisionStrategy(String clientUuid) {
    JsonNode settings = adminGet(authzPath(clientUuid) + "/settings");
    if (!(settings instanceof ObjectNode resourceServer)) {
      throw new IllegalStateException("Unexpected resource server settings: " + settings);
    }
    resourceServer.put("decisionStrategy", "AFFIRMATIVE");
    adminPut(authzPath(clientUuid), resourceServer);
  }

  private void createScopes(String clientUuid) {
    // One authorization scope per Polaris operation: Keycloak matches action.name against these.
    for (PolarisAuthorizableOperation operation : PolarisAuthorizableOperation.values()) {
      adminPost(authzPath(clientUuid) + "/scope", Map.of("name", operation.name()));
    }
  }

  private void createResources(String clientUuid) {
    List<Map<String, String>> scopes =
        allOperationNames().stream().map(name -> Map.of("name", name)).collect(Collectors.toList());
    for (String type : polarisResourceTypes()) {
      adminPost(
          authzPath(clientUuid) + "/resource",
          Map.of("name", type, "type", RESOURCE_TYPE_PREFIX + type, "scopes", scopes));
    }
  }

  private void createUserPolicy(String clientUuid, String name, String user) {
    adminPost(authzPath(clientUuid) + "/policy/user", Map.of("name", name, "users", List.of(user)));
  }

  private void createScopePermission(
      String clientUuid, String name, List<String> scopes, String policy) {
    adminPost(
        authzPath(clientUuid) + "/permission/scope",
        Map.of(
            "name",
            name,
            "decisionStrategy",
            "AFFIRMATIVE",
            "resources",
            polarisResourceTypes(),
            "scopes",
            scopes,
            "policies",
            List.of(policy)));
  }

  /**
   * The Polaris entity types that can appear as an AuthZEN resource, including {@code ROOT} for
   * realm-scoped operations.
   */
  private static List<String> polarisResourceTypes() {
    return Stream.of(PolarisEntityType.values())
        .filter(type -> type != PolarisEntityType.NULL_TYPE)
        .map(PolarisEntityType::name)
        .collect(Collectors.toList());
  }

  private static List<String> allOperationNames() {
    return Arrays.stream(PolarisAuthorizableOperation.values())
        .map(PolarisAuthorizableOperation::name)
        .collect(Collectors.toList());
  }

  private static List<String> readOnlyOperationNames() {
    return READ_ONLY_OPERATIONS.stream()
        .map(PolarisAuthorizableOperation::name)
        .sorted()
        .collect(Collectors.toList());
  }

  private String authzPath(String clientUuid) {
    return "/clients/" + clientUuid + "/authz/resource-server";
  }

  private JsonNode adminGet(String path) {
    HttpRequest request =
        HttpRequest.newBuilder()
            .uri(adminUri(path))
            .header("Authorization", "Bearer " + keycloak.getAdminToken())
            .GET()
            .build();
    HttpResponse<String> response = send(request);
    if (response.statusCode() != 200) {
      throw new IllegalStateException(
          "Keycloak admin GET " + path + " failed with " + response.statusCode());
    }
    try {
      return MAPPER.readTree(response.body());
    } catch (Exception e) {
      throw new IllegalStateException("Could not parse Keycloak admin response for " + path, e);
    }
  }

  private void adminPut(String path, Object body) {
    adminWrite("PUT", path, body);
  }

  private void adminPost(String path, Object body) {
    adminWrite("POST", path, body);
  }

  private void adminWrite(String method, String path, Object body) {
    String json;
    try {
      json = MAPPER.writeValueAsString(body);
    } catch (Exception e) {
      throw new IllegalStateException("Could not serialize Keycloak admin request", e);
    }
    HttpRequest request =
        HttpRequest.newBuilder()
            .uri(adminUri(path))
            .header("Authorization", "Bearer " + keycloak.getAdminToken())
            .header("Content-Type", "application/json")
            .method(method, HttpRequest.BodyPublishers.ofString(json))
            .build();
    HttpResponse<String> response = send(request);
    int status = response.statusCode();
    // 409 means the object already exists, which is fine for an idempotent setup.
    if (status != 200 && status != 201 && status != 204 && status != 409) {
      throw new IllegalStateException(
          "Keycloak admin "
              + method
              + " "
              + path
              + " failed with "
              + status
              + ": "
              + response.body()
              + "\nKeycloak logs:\n"
              + keycloak.getLogs());
    }
  }

  private URI adminUri(String path) {
    return URI.create(keycloak.getBaseUrl() + "/admin/realms/" + keycloak.getRealm() + path);
  }

  private HttpResponse<String> send(HttpRequest request) {
    try {
      return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException("Interrupted while calling the Keycloak admin API", e);
    } catch (Exception e) {
      throw new IllegalStateException("Keycloak admin API call failed", e);
    }
  }
}
