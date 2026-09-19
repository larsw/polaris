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

import java.time.Duration
import org.gradle.api.attributes.java.TargetJvmVersion
import org.gradle.api.plugins.jvm.JvmTestSuite

plugins {
  id("polaris-server")
  id("polaris-server-test-runner")
  id("org.kordamp.gradle.jandex")
}

val intTestJvmVersion = 21
val authzenStartupAction = sourceSets.create("authzenStartupAction")
val authzenStartupActionCompileOnly = configurations.getByName("authzenStartupActionCompileOnly")
val authzenStartupActionImplementation =
  configurations.getByName("authzenStartupActionImplementation")

description = "Polaris authorization via an AuthZEN-compliant Policy Decision Point"

dependencies {
  polarisServer(project(path = ":polaris-server", configuration = "quarkusRunner"))

  implementation(project(":polaris-core"))
  implementation(project(":polaris-extensions-auth-common"))
  implementation(libs.apache.httpclient5)
  implementation(platform(libs.jackson.bom))
  implementation("com.fasterxml.jackson.core:jackson-core")
  implementation("com.fasterxml.jackson.core:jackson-databind")
  implementation(libs.guava)
  implementation(libs.slf4j.api)
  implementation(project(":polaris-async-api"))

  // Iceberg dependency for ForbiddenException
  implementation(platform(libs.iceberg.bom))
  implementation("org.apache.iceberg:iceberg-api")

  compileOnly(project(":polaris-immutables"))
  annotationProcessor(project(":polaris-immutables", configuration = "processor"))

  compileOnly(libs.jspecify)
  compileOnly(libs.jakarta.annotation.api)
  compileOnly(libs.jakarta.enterprise.cdi.api)
  compileOnly(libs.jakarta.inject.api)
  compileOnly(libs.smallrye.config.core)

  testCompileOnly(project(":polaris-immutables"))
  testAnnotationProcessor(project(":polaris-immutables", configuration = "processor"))
  testCompileOnly(libs.jspecify)

  testImplementation(testFixtures(project(":polaris-core")))
  testImplementation(platform(libs.junit.bom))
  testImplementation("org.junit.jupiter:junit-jupiter")
  testImplementation(libs.assertj.core)
  testImplementation(libs.mockito.core)
  testImplementation(testFixtures(project(":polaris-async-api")))
  testImplementation(project(":polaris-async-java"))
  testImplementation(project(":polaris-idgen-mocks"))

  authzenStartupActionCompileOnly(
    "org.apache.polaris.server-test-runner:polaris-server-test-runner"
  )
  authzenStartupActionImplementation(project(":polaris-core"))
  authzenStartupActionImplementation(project(":polaris-keycloak-testcontainer"))
  authzenStartupActionImplementation(platform(libs.testcontainers.bom))
  authzenStartupActionImplementation("org.testcontainers:testcontainers")
  authzenStartupActionImplementation(platform(libs.jackson.bom))
  authzenStartupActionImplementation("com.fasterxml.jackson.core:jackson-databind")
}

testing {
  suites {
    @Suppress("UnstableApiUsage")
    register<JvmTestSuite>("intTest") {
      useJUnitJupiter()
      dependencies {
        implementation(platform(libs.quarkus.bom))
        implementation("io.rest-assured:rest-assured")
        implementation(project(":polaris-tests"))
        implementation(project(":polaris-runtime-test-common"))
        implementation(project(":polaris-api-management-model"))
        implementation(platform(libs.iceberg.bom))
        implementation("org.apache.iceberg:iceberg-api")
        implementation("org.apache.iceberg:iceberg-core")
        implementation(platform(libs.jackson.bom))
        implementation("com.fasterxml.jackson.core:jackson-databind")
      }
      targets {
        all {
          val buildDir = project.layout.buildDirectory
          testTask.configure {
            description =
              "Runs AuthZEN integration tests against an external Polaris server backed by Keycloak."

            val apiVersion = providers.environmentVariable("DOCKER_API_VERSION").getOrElse("1.44")
            systemProperty("api.version", apiVersion)
            jvmArgs("--add-exports", "java.base/sun.nio.ch=ALL-UNNAMED")
            systemProperty("java.security.manager", "allow")
            maxParallelForks = 1

            val logsDir = buildDir.get().asFile.resolve("logs/intTest")
            // Lets a test assert which AuthZEN endpoint the server actually called, which is the
            // only way to tell a batched evaluation from a series of single ones from outside the
            // server process.
            systemProperty("polaris.it.server-log", logsDir.resolve("polaris.log").absolutePath)

            withPolarisServer(configurations.polarisServer) {
              startupActionClasspath.from(authzenStartupAction.runtimeClasspath)
              startupActionClass.set(
                "org.apache.polaris.extension.auth.authzen.test.AuthzenStartupAction"
              )
              // The authorizer resolves the PDP endpoints and fetches its first token while the
              // server starts, so allow more than the default headroom.
              startupTimeout.set(Duration.ofSeconds(90))

              environment.put(
                "AWS_REGION",
                providers.environmentVariable("AWS_REGION").orElse("us-west-2"),
              )
              environment.putAll(
                mapOf("POLARIS_BOOTSTRAP_CREDENTIALS" to "POLARIS,test-admin,test-secret")
              )
              systemProperties.putAll(
                mapOf(
                  "quarkus.log.file.path" to logsDir.resolve("polaris.log").absolutePath,
                  "polaris.authorization.type" to "authzen",
                  "polaris.features.\"SUPPORTED_CATALOG_STORAGE_TYPES\"" to "[\"FILE\"]",
                  "polaris.features.\"ALLOW_INSECURE_STORAGE_TYPES\"" to "true",
                  // The test PDP is reached over plain HTTP, which the readiness check rightly
                  // flags as severe when credentials are sent to it.
                  "polaris.readiness.ignore-severe-issues" to "true",
                  // Log the exact AuthZEN payloads, so a denied test is diagnosable from the
                  // server log rather than by packet capture.
                  "quarkus.log.category.\"org.apache.polaris.extension.auth.authzen\".level" to
                    "DEBUG",
                )
              )
            }

            // Registered after withPolarisServer so that it runs before it: Gradle executes
            // doFirst actions in reverse registration order, and wiping the directory after the
            // server has started would throw the log away.
            doFirst {
              logsDir.deleteRecursively()
              buildDir.get().asFile.resolve("quarkus.log").delete()
            }
          }
        }
      }
    }
  }
}

listOf(
    "intTestCompileClasspath",
    "intTestRuntimeClasspath",
    "authzenStartupActionCompileClasspath",
    "authzenStartupActionRuntimeClasspath",
  )
  .forEach {
    configurations.named(it).configure {
      attributes.attribute(TargetJvmVersion.TARGET_JVM_VERSION_ATTRIBUTE, intTestJvmVersion)
    }
  }

tasks.named("check") { dependsOn("intTest") }
