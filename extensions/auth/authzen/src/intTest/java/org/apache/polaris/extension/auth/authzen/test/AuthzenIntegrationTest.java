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

import static io.restassured.RestAssured.given;

import io.restassured.http.ContentType;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * End-to-end tests against a real Keycloak acting as an AuthZEN Policy Decision Point.
 *
 * <p>The realm is configured by {@code AuthzenStartupAction}: the Polaris principal {@code root}
 * may do anything, {@code analyst} may only read, and any other principal -- having no Keycloak
 * user at all -- is denied.
 */
public class AuthzenIntegrationTest extends AuthzenIntegrationTestBase {

  @Test
  void permittedPrincipalCanListCatalogs() {
    given()
        .header("Authorization", "Bearer " + getRootToken())
        .when()
        .get("/api/management/v1/catalogs")
        .then()
        .statusCode(200);
  }

  @Test
  void unknownPrincipalIsDenied() {
    // "stranger" is a Polaris principal with no matching Keycloak user, so the PDP denies it.
    String strangerToken = createOrReplacePrincipalAndGetToken("stranger");

    given()
        .header("Authorization", "Bearer " + strangerToken)
        .when()
        .get("/api/management/v1/catalogs")
        .then()
        .statusCode(403);
  }

  @Test
  void readOnlyPrincipalCanReadButNotWrite() {
    String analystToken = createOrReplacePrincipalAndGetToken("analyst");

    given()
        .header("Authorization", "Bearer " + analystToken)
        .when()
        .get("/api/management/v1/catalogs")
        .then()
        .statusCode(200);

    Map<String, Object> catalog =
        Map.of(
            "type",
            "INTERNAL",
            "name",
            "analyst_catalog_" + UUID.randomUUID().toString().substring(0, 8),
            "properties",
            Map.of("default-base-location", "file:///tmp/polaris-authzen-it"),
            "storageConfigInfo",
            Map.of("storageType", "FILE", "allowedLocations", List.of("file:///tmp/")));

    given()
        .contentType(ContentType.JSON)
        .header("Authorization", "Bearer " + analystToken)
        .body(toJson(catalog))
        .when()
        .post("/api/management/v1/catalogs")
        .then()
        .statusCode(403);
  }

  @Test
  void permittedPrincipalCanCreateCatalogAndNamespace() {
    String rootToken = getRootToken();
    String catalogName = "authzen_catalog_" + UUID.randomUUID().toString().substring(0, 8);

    createFileCatalog(
        rootToken,
        catalogName,
        "file:///tmp/polaris-authzen-it/" + catalogName,
        List.of("file:///tmp/polaris-authzen-it/" + catalogName));

    createNamespace(rootToken, catalogName, "sales");

    given()
        .header("Authorization", "Bearer " + rootToken)
        .when()
        .get("/api/catalog/v1/{cat}/namespaces", catalogName)
        .then()
        .statusCode(200);
  }

  @Test
  void readOnlyPrincipalCannotCreateANamespaceInAnExistingCatalog() {
    String rootToken = getRootToken();
    String analystToken = createOrReplacePrincipalAndGetToken("analyst");
    String catalogName = "authzen_shared_" + UUID.randomUUID().toString().substring(0, 8);

    createFileCatalog(
        rootToken,
        catalogName,
        "file:///tmp/polaris-authzen-it/" + catalogName,
        List.of("file:///tmp/polaris-authzen-it/" + catalogName));

    given()
        .header("Authorization", "Bearer " + analystToken)
        .when()
        .get("/api/catalog/v1/{cat}/namespaces", catalogName)
        .then()
        .statusCode(200);

    given()
        .contentType(ContentType.JSON)
        .header("Authorization", "Bearer " + analystToken)
        .body(toJson(Map.of("namespace", List.of("forbidden"))))
        .when()
        .post("/api/catalog/v1/{cat}/namespaces", catalogName)
        .then()
        .statusCode(403);
  }
}
