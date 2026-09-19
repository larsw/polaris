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
import static org.assertj.core.api.Assertions.assertThat;

import io.restassured.http.ContentType;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.apache.iceberg.PartitionSpec;
import org.apache.iceberg.Schema;
import org.apache.iceberg.TableMetadata;
import org.apache.iceberg.TableMetadataParser;
import org.apache.iceberg.types.Types;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Covers the batched Access Evaluations path against a real Keycloak PDP.
 *
 * <p>{@code commitTransaction} is the only Polaris operation that authorizes more than one intent
 * in a single request -- one per table in the transaction -- so it is the only way to reach the
 * batch path through the server. Everything else authorizes a single intent and takes the single
 * Access Evaluation endpoint.
 */
public class AuthzenCommitTransactionIT extends AuthzenIntegrationTestBase {

  private static final String EVALUATIONS_ENDPOINT = "/authzen/access/v1/evaluations";

  private String catalogName;
  private String namespace;
  private String baseLocation;
  private String rootToken;
  private String firstTable;
  private String secondTable;

  @BeforeEach
  void setUpTwoTables(@TempDir Path tempDir) throws Exception {
    rootToken = getRootToken();
    catalogName = "authzen_txn_" + UUID.randomUUID().toString().replace("-", "");
    namespace = "ns_" + UUID.randomUUID().toString().replace("-", "");
    firstTable = "tbl_a_" + UUID.randomUUID().toString().replace("-", "");
    secondTable = "tbl_b_" + UUID.randomUUID().toString().replace("-", "");

    Path warehouse = tempDir.resolve("warehouse");
    Files.createDirectory(warehouse);
    baseLocation = warehouse.toUri().toString();
    String namespacePath = baseLocation + (baseLocation.endsWith("/") ? "" : "/") + namespace;

    createFileCatalog(
        rootToken,
        catalogName,
        baseLocation,
        List.of(baseLocation, namespacePath, namespacePath + "/"));
    createNamespace(rootToken, catalogName, namespace);
    registerTable(firstTable);
    registerTable(secondTable);
  }

  @Test
  void aTransactionOverTwoTablesIsAuthorizedInOneBatchedCall() throws Exception {
    long logOffset = serverLogLength();

    given()
        .contentType(ContentType.JSON)
        .header("Authorization", "Bearer " + rootToken)
        .body(toJson(commitTransactionRequest()))
        .when()
        .post("/api/catalog/v1/{cat}/transactions/commit", catalogName)
        .then()
        .statusCode(204);

    // One batched call, carrying one evaluation per table of the transaction.
    String batched = awaitLogLineContaining(logOffset, EVALUATIONS_ENDPOINT);
    assertThat(batched)
        .contains("\"evaluations_semantic\":\"deny_on_first_deny\"")
        .contains("COMMIT_TRANSACTION")
        .contains(firstTable)
        .contains(secondTable);
  }

  @Test
  void aTransactionIsDeniedWhenThePdpDeniesTheFirstEvaluation() throws Exception {
    String analystToken = createOrReplacePrincipalAndGetToken("analyst");
    long logOffset = serverLogLength();

    // The read-only principal has no COMMIT_TRANSACTION permission, so the PDP denies the first
    // evaluation and stops there.
    given()
        .contentType(ContentType.JSON)
        .header("Authorization", "Bearer " + analystToken)
        .body(toJson(commitTransactionRequest()))
        .when()
        .post("/api/catalog/v1/{cat}/transactions/commit", catalogName)
        .then()
        .statusCode(403);

    assertThat(awaitLogLineContaining(logOffset, EVALUATIONS_ENDPOINT))
        .contains("COMMIT_TRANSACTION");
  }

  private Map<String, Object> commitTransactionRequest() {
    return Map.of("table-changes", List.of(tableChange(firstTable), tableChange(secondTable)));
  }

  private Map<String, Object> tableChange(String tableName) {
    return Map.of(
        "identifier",
        Map.of("namespace", List.of(namespace), "name", tableName),
        "requirements",
        List.of(),
        "updates",
        List.of(Map.of("action", "set-properties", "updates", Map.of("authzen-it", "true"))));
  }

  private void registerTable(String tableName) throws Exception {
    String tableLocation =
        baseLocation + (baseLocation.endsWith("/") ? "" : "/") + namespace + "/" + tableName;
    Path metadataPath =
        Path.of(
            URI.create(
                tableLocation
                    + (tableLocation.endsWith("/") ? "" : "/")
                    + "metadata/v1.metadata.json"));
    Files.createDirectories(metadataPath.getParent());
    Schema schema =
        new Schema(
            Types.NestedField.required(1, "id", Types.LongType.get()),
            Types.NestedField.required(2, "data", Types.StringType.get()));
    TableMetadata tableMetadata =
        TableMetadata.newTableMetadata(
            schema, PartitionSpec.unpartitioned(), tableLocation, Map.of());
    Files.writeString(metadataPath, TableMetadataParser.toJson(tableMetadata));

    given()
        .contentType(ContentType.JSON)
        .header("Authorization", "Bearer " + rootToken)
        .body(
            toJson(
                Map.of(
                    "name",
                    tableName,
                    "metadata-location",
                    metadataPath.toUri().toString(),
                    "stage-create",
                    false)))
        .when()
        .post("/api/catalog/v1/{cat}/namespaces/{ns}/register", catalogName, namespace)
        .then()
        .statusCode(200);
  }

  /**
   * The server log, which the build points at a known path, is the only place outside the server
   * process that records which AuthZEN endpoint was called.
   */
  private static Path serverLog() {
    String path = System.getProperty("polaris.it.server-log");
    assertThat(path).as("system property polaris.it.server-log").isNotNull();
    return Path.of(path);
  }

  private static long serverLogLength() throws IOException {
    Path log = serverLog();
    return Files.exists(log) ? Files.size(log) : 0L;
  }

  /**
   * Waits for a log line written after {@code offset} that contains {@code needle}, and returns it.
   *
   * <p>The log is written by another process, so the line may not have been flushed by the time the
   * HTTP response arrives.
   */
  private static String awaitLogLineContaining(long offset, String needle)
      throws IOException, InterruptedException {
    for (int attempt = 0; attempt < 50; attempt++) {
      for (String line : newLogLines(offset)) {
        if (line.contains(needle)) {
          return line;
        }
      }
      Thread.sleep(100);
    }
    throw new AssertionError(
        "No server log line containing '" + needle + "' appeared within 5 seconds");
  }

  private static List<String> newLogLines(long offset) throws IOException {
    Path log = serverLog();
    if (!Files.exists(log)) {
      return List.of();
    }
    byte[] all = Files.readAllBytes(log);
    if (all.length <= offset) {
      return List.of();
    }
    String tail =
        new String(all, (int) offset, (int) (all.length - offset), StandardCharsets.UTF_8);
    return List.of(tail.split("\n"));
  }
}
