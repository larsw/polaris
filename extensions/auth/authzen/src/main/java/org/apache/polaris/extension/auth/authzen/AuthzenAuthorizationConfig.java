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

import static com.google.common.base.Preconditions.checkArgument;

import com.google.common.base.Strings;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;
import java.net.URI;
import java.time.Duration;
import java.util.Optional;
import org.apache.polaris.extension.auth.common.config.BearerTokenConfig;
import org.apache.polaris.extension.auth.common.config.PdpHttpConfig;
import org.apache.polaris.immutables.PolarisImmutable;

/**
 * Configuration for authorization against an AuthZEN-compliant Policy Decision Point.
 *
 * <p><strong>Preview Feature:</strong> AuthZEN authorization is currently a preview feature and is
 * not a stable release. It may undergo breaking changes in future versions. Use with caution in
 * production environments.
 */
@PolarisImmutable
@ConfigMapping(prefix = "polaris.authorization.authzen")
public interface AuthzenAuthorizationConfig {

  /** Authentication types supported when calling the AuthZEN PDP */
  enum AuthenticationType {
    NONE,
    BEARER,
    CLIENT_CREDENTIALS
  }

  /** How the {@code resource.id} sent to the PDP is derived from the Polaris resource path */
  enum ResourceIdFormat {
    /** The full path, for example {@code my_catalog/schema1/my_table} */
    PATH,
    /** The unqualified leaf name, for example {@code my_table} */
    NAME,
    /**
     * The Polaris entity type, for example {@code TABLE_LIKE}.
     *
     * <p>For PDPs that resolve {@code resource.id} against resources registered ahead of time --
     * Keycloak works this way -- an id derived from the catalog, namespace or table name can never
     * match, because those are created at runtime. This format keeps the id to the finite set of
     * Polaris entity types, so every resource a policy needs can be registered up front. The
     * instance being accessed is still described by {@code resource.properties}.
     */
    TYPE
  }

  /** How the Polaris operation name is cased before being sent as {@code action.name} */
  enum ActionNameCase {
    /** The operation name as declared, for example {@code LOAD_TABLE_WITH_READ_DELEGATION} */
    AS_IS,
    /** The operation name lower-cased, for example {@code load_table_with_read_delegation} */
    LOWER
  }

  /**
   * Base URI of the PDP, used to discover the evaluation endpoints via its {@code
   * .well-known/authzen-configuration} document. For Keycloak this is the realm URI, for example
   * {@code https://keycloak.example.com/realms/demo}.
   */
  Optional<URI> pdpUri();

  /**
   * Explicit URI of the Access Evaluation endpoint. Set this to bypass discovery; it takes
   * precedence over the endpoint advertised by the PDP metadata.
   */
  Optional<URI> accessEvaluationEndpoint();

  /**
   * Explicit URI of the Access Evaluations (batch) endpoint. Set this to bypass discovery; it takes
   * precedence over the endpoint advertised by the PDP metadata.
   */
  Optional<URI> accessEvaluationsEndpoint();

  /**
   * Whether to batch the intents of one authorization request into a single Access Evaluations
   * call. When disabled, or when the PDP advertises no batch endpoint, Polaris falls back to one
   * Access Evaluation call per intent.
   */
  @WithDefault("true")
  boolean useBatchEndpoint();

  MappingConfig mapping();

  AuthenticationConfig auth();

  PdpHttpConfig http();

  /** Validates the complete AuthZEN configuration */
  default void validate() {
    checkArgument(
        pdpUri().isPresent() || accessEvaluationEndpoint().isPresent(),
        "One of polaris.authorization.authzen.pdp-uri or "
            + "polaris.authorization.authzen.access-evaluation-endpoint must be configured");

    pdpUri().ifPresent(uri -> checkHttpUri(uri, "pdp-uri"));
    accessEvaluationEndpoint().ifPresent(uri -> checkHttpUri(uri, "access-evaluation-endpoint"));
    accessEvaluationsEndpoint().ifPresent(uri -> checkHttpUri(uri, "access-evaluations-endpoint"));

    auth().validate();
  }

  private static void checkHttpUri(URI uri, String property) {
    String scheme = uri.getScheme();
    checkArgument(
        "http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme),
        "polaris.authorization.authzen."
            + property
            + " must use http or https scheme, but got: "
            + scheme);
  }

  /**
   * Controls how Polaris concepts are rendered into the AuthZEN payload.
   *
   * <p>The defaults produce a self-describing payload. PDPs that match on specific strings need
   * these knobs: Keycloak, for instance, resolves subjects by username only when the id carries a
   * {@code username:} prefix.
   */
  @PolarisImmutable
  interface MappingConfig {
    /** The value sent as {@code subject.type} */
    @WithDefault("user")
    String subjectType();

    /** A prefix prepended to the principal name when building {@code subject.id} */
    Optional<String> subjectIdPrefix();

    /** A prefix prepended to the Polaris entity type when building {@code resource.type} */
    Optional<String> resourceTypePrefix();

    /** How {@code resource.id} is derived from the resource path */
    @WithDefault("path")
    ResourceIdFormat resourceIdFormat();

    /**
     * The separator used to join path segments when {@code resource-id-format} is {@code path}.
     * Polaris entity names may themselves contain this separator, so a policy that needs an
     * unambiguous path should read {@code resource.properties.parents} instead.
     */
    @WithDefault("/")
    String resourceIdSeparator();

    /** How the Polaris operation name is cased before being sent as {@code action.name} */
    @WithDefault("as-is")
    ActionNameCase actionNameCase();

    /**
     * The {@code resource.type} used for operations that act on the realm as a whole rather than on
     * a specific entity, such as {@code LIST_CATALOGS}. The realm identifier is sent as the {@code
     * resource.id}.
     */
    @WithDefault("ROOT")
    String rootResourceType();
  }

  /** Authentication configuration for calls to the AuthZEN PDP. */
  @PolarisImmutable
  interface AuthenticationConfig {
    /** Type of authentication */
    @WithDefault("none")
    AuthenticationType type();

    /** Bearer token authentication configuration */
    Optional<BearerTokenConfig> bearer();

    /** OAuth2 client credentials authentication configuration */
    Optional<ClientCredentialsConfig> clientCredentials();

    default void validate() {
      switch (type()) {
        case BEARER:
          checkArgument(
              bearer().isPresent(), "Bearer configuration is required when type is 'bearer'");
          bearer().get().validate();
          break;
        case CLIENT_CREDENTIALS:
          checkArgument(
              clientCredentials().isPresent(),
              "Client credentials configuration is required when type is 'client-credentials'");
          clientCredentials().get().validate();
          break;
        case NONE:
          // No authentication - nothing to validate
          break;
        default:
          throw new IllegalArgumentException(
              "Invalid authentication type: "
                  + type()
                  + ". Supported types: 'none', 'bearer', 'client-credentials'");
      }
    }
  }

  /**
   * Configuration for the OAuth2 {@code client_credentials} grant.
   *
   * <p>PDPs that are themselves authorization servers issue short-lived access tokens, so Polaris
   * fetches and refreshes one rather than relying on a token supplied out of band.
   */
  @PolarisImmutable
  interface ClientCredentialsConfig {
    /** The OAuth2 token endpoint to request access tokens from */
    URI tokenEndpoint();

    /** The OAuth2 client id */
    String clientId();

    /** The OAuth2 client secret */
    String clientSecret();

    /** An optional space-delimited scope string to request */
    Optional<String> scope();

    /** How long before a token expires it is refreshed. Defaults to 1 minute if not specified. */
    Optional<Duration> expirationBuffer();

    /**
     * How often to refresh the token when the token endpoint does not report a lifetime. Defaults
     * to 5 minutes if not specified.
     */
    Optional<Duration> refreshInterval();

    /**
     * How long to wait for the first token to be fetched before failing a request. Defaults to 5
     * seconds.
     */
    Optional<Duration> initialTokenWait();

    /** How long to wait before retrying after a failed token fetch. Defaults to 1 second. */
    Optional<Duration> refreshRetryInterval();

    default void validate() {
      String scheme = tokenEndpoint().getScheme();
      checkArgument(
          "http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme),
          "polaris.authorization.authzen.auth.client-credentials.token-endpoint must use http or https scheme, but got: "
              + scheme);
      checkArgument(!Strings.isNullOrEmpty(clientId()), "Client id cannot be null or empty");
      checkArgument(
          !Strings.isNullOrEmpty(clientSecret()), "Client secret cannot be null or empty");
      checkArgument(
          expirationBuffer().isEmpty() || expirationBuffer().get().isPositive(),
          "expirationBuffer must be positive");
      checkArgument(
          refreshInterval().isEmpty() || refreshInterval().get().isPositive(),
          "refreshInterval must be positive");
      checkArgument(
          initialTokenWait().isEmpty() || initialTokenWait().get().isPositive(),
          "initialTokenWait must be positive");
      checkArgument(
          refreshRetryInterval().isEmpty() || refreshRetryInterval().get().isPositive(),
          "refreshRetryInterval must be positive");
    }
  }
}
