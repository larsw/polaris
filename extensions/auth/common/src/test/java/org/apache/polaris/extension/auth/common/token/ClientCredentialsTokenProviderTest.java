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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

import com.fasterxml.jackson.databind.json.JsonMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.polaris.ids.mocks.MutableMonotonicClock;
import org.apache.polaris.nosql.async.MockAsyncExec;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class ClientCredentialsTokenProviderTest {

  private HttpServer server;
  private CloseableHttpClient httpClient;
  private MutableMonotonicClock clock;
  private MockAsyncExec asyncExec;

  private final AtomicInteger tokenCounter = new AtomicInteger();
  private final AtomicReference<Response> nextResponse = new AtomicReference<>();
  private final List<String> requestBodies = new ArrayList<>();

  @BeforeEach
  void setUp() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/token", this::handleToken);
    server.start();
    httpClient = HttpClients.createDefault();
    clock = new MutableMonotonicClock();
    asyncExec = new MockAsyncExec(clock);
  }

  @AfterEach
  void tearDown() throws IOException {
    httpClient.close();
    server.stop(0);
  }

  private void handleToken(HttpExchange exchange) throws IOException {
    synchronized (requestBodies) {
      requestBodies.add(
          new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
    }
    Response response = nextResponse.get();
    if (response == null) {
      response =
          new Response(
              200,
              "{\"access_token\":\"tok-"
                  + tokenCounter.incrementAndGet()
                  + "\",\"expires_in\":300}");
    }
    byte[] bytes = response.body().getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().add("Content-Type", "application/json");
    exchange.sendResponseHeaders(response.status(), bytes.length);
    try (OutputStream out = exchange.getResponseBody()) {
      out.write(bytes);
    }
  }

  private ClientCredentialsTokenProvider provider() {
    return new ClientCredentialsTokenProvider(
        URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/token"),
        "polaris-pdp",
        "s3cr3t",
        "authz",
        Duration.ofMinutes(1),
        Duration.ofMinutes(5),
        Duration.ofMillis(1),
        Duration.ofSeconds(1),
        httpClient,
        JsonMapper.builder().build(),
        asyncExec,
        clock::currentInstant);
  }

  private void runScheduledTasks() {
    asyncExec.readyCallables().forEach(MockAsyncExec.Task::call);
  }

  @Test
  void fetchesATokenOnTheFirstScheduledRefresh() {
    try (ClientCredentialsTokenProvider provider = provider()) {
      // nothing has run yet, so getToken() gives up after the initial wait
      assertThatIllegalStateException()
          .isThrownBy(provider::getToken)
          .withMessageStartingWith("Failed to obtain initial PDP bearer token");

      assertThat(asyncExec.readyCount()).isEqualTo(1);
      runScheduledTasks();

      assertThat(provider.getToken()).isEqualTo("tok-1");
      assertThat(requestBodies.get(0))
          .contains("grant_type=client_credentials")
          .contains("client_id=polaris-pdp")
          .contains("client_secret=s3cr3t")
          .contains("scope=authz");
    }
  }

  @Test
  void refreshesBeforeTheTokenExpires() {
    try (ClientCredentialsTokenProvider provider = provider()) {
      runScheduledTasks();
      assertThat(provider.getToken()).isEqualTo("tok-1");

      // expires_in is 300s and the buffer is 60s, so nothing is due before 240s
      clock.advanceBoth(Duration.ofSeconds(239));
      assertThat(asyncExec.readyCount()).isEqualTo(0);

      clock.advanceBoth(Duration.ofSeconds(1));
      assertThat(asyncExec.readyCount()).isEqualTo(1);
      runScheduledTasks();

      assertThat(provider.getToken()).isEqualTo("tok-2");
    }
  }

  @Test
  void retriesAfterAFailedTokenRequest() {
    nextResponse.set(new Response(401, "{\"error\":\"invalid_client\"}"));

    try (ClientCredentialsTokenProvider provider = provider()) {
      runScheduledTasks();

      assertThatIllegalStateException().isThrownBy(provider::getToken);

      // a retry is scheduled one second out
      clock.advanceBoth(Duration.ofSeconds(1));
      assertThat(asyncExec.readyCount()).isEqualTo(1);

      nextResponse.set(null);
      runScheduledTasks();

      assertThat(provider.getToken()).isEqualTo("tok-1");
    }
  }

  @Test
  void treatsAResponseWithoutAnAccessTokenAsAFailure() {
    nextResponse.set(new Response(200, "{\"token_type\":\"Bearer\"}"));

    try (ClientCredentialsTokenProvider provider = provider()) {
      runScheduledTasks();
      assertThatIllegalStateException().isThrownBy(provider::getToken);

      clock.advanceBoth(Duration.ofSeconds(1));
      nextResponse.set(null);
      runScheduledTasks();

      assertThat(provider.getToken()).isEqualTo("tok-1");
    }
  }

  @Test
  void fallsBackToTheFixedIntervalWhenNoLifetimeIsReported() {
    nextResponse.set(new Response(200, "{\"access_token\":\"opaque-token\"}"));

    try (ClientCredentialsTokenProvider provider = provider()) {
      runScheduledTasks();
      assertThat(provider.getToken()).isEqualTo("opaque-token");

      // no expires_in and not a JWT, so the 5 minute fallback interval applies
      clock.advanceBoth(Duration.ofSeconds(299));
      assertThat(asyncExec.readyCount()).isEqualTo(0);

      clock.advanceBoth(Duration.ofSeconds(1));
      assertThat(asyncExec.readyCount()).isEqualTo(1);
    }
  }

  @Test
  void stopsSchedulingOnceClosed() {
    ClientCredentialsTokenProvider provider = provider();
    runScheduledTasks();
    assertThat(provider.getToken()).isEqualTo("tok-1");

    provider.close();

    clock.advanceBoth(Duration.ofMinutes(10));
    assertThat(asyncExec.readyCount()).isEqualTo(0);
  }

  private record Response(int status, String body) {}
}
