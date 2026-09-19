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

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A minimal in-process AuthZEN Policy Decision Point, scripted per test.
 *
 * <p>It answers the discovery document and whatever the test queues up for the evaluation and
 * evaluations endpoints, and records the requests it received so tests can assert on the payload
 * and on the headers Polaris sends.
 */
final class StubAuthzenPdp implements AutoCloseable {

  private final HttpServer server;
  private final List<String> bodies = new ArrayList<>();
  private final List<Map<String, String>> headers = new ArrayList<>();
  private final Map<String, Response> responses = new ConcurrentHashMap<>();
  private final boolean advertiseBatchEndpoint;

  StubAuthzenPdp() throws IOException {
    this(true);
  }

  StubAuthzenPdp(boolean advertiseBatchEndpoint) throws IOException {
    this.advertiseBatchEndpoint = advertiseBatchEndpoint;
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/.well-known/authzen-configuration", this::handleDiscovery);
    server.createContext("/access/v1/evaluation", exchange -> handleScripted(exchange, "single"));
    server.createContext("/access/v1/evaluations", exchange -> handleScripted(exchange, "batch"));
    server.start();
  }

  URI pdpUri() {
    return URI.create("http://127.0.0.1:" + server.getAddress().getPort());
  }

  /** Scripts the response of the single-evaluation endpoint. */
  void onEvaluation(int status, String body) {
    responses.put("single", new Response(status, body));
  }

  /** Scripts the response of the batch endpoint. */
  void onEvaluations(int status, String body) {
    responses.put("batch", new Response(status, body));
  }

  /** The bodies of the evaluation requests received so far, in order. */
  List<String> requestBodies() {
    return List.copyOf(bodies);
  }

  /** The headers of the evaluation requests received so far, in order. */
  List<Map<String, String>> requestHeaders() {
    return List.copyOf(headers);
  }

  @Override
  public void close() {
    server.stop(0);
  }

  private void handleDiscovery(HttpExchange exchange) throws IOException {
    String base = "http://127.0.0.1:" + server.getAddress().getPort();
    String body =
        advertiseBatchEndpoint
            ? """
              {
                "policy_decision_point": "%s",
                "access_evaluation_endpoint": "%s/access/v1/evaluation",
                "access_evaluations_endpoint": "%s/access/v1/evaluations"
              }
              """
                .formatted(base, base, base)
            : """
              {
                "policy_decision_point": "%s",
                "access_evaluation_endpoint": "%s/access/v1/evaluation"
              }
              """
                .formatted(base, base);
    respond(exchange, 200, body);
  }

  private void handleScripted(HttpExchange exchange, String key) throws IOException {
    synchronized (this) {
      bodies.add(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
      Map<String, String> captured = new java.util.HashMap<>();
      exchange
          .getRequestHeaders()
          .forEach((name, values) -> captured.put(name, String.join(",", values)));
      headers.add(captured);
    }
    Response response = responses.getOrDefault(key, new Response(200, "{\"decision\":true}"));
    respond(exchange, response.status(), response.body());
  }

  private static void respond(HttpExchange exchange, int status, String body) throws IOException {
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().add("Content-Type", "application/json");
    exchange.sendResponseHeaders(status, bytes.length);
    try (OutputStream out = exchange.getResponseBody()) {
      out.write(bytes);
    }
  }

  private record Response(int status, String body) {}
}
