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

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.apache.polaris.core.auth.PolarisAuthorizerFactory;
import org.apache.polaris.core.config.ProductionReadinessCheck;
import org.apache.polaris.core.config.ProductionReadinessCheck.Error;

@ApplicationScoped
public class AuthzenProductionReadinessChecks {

  @Produces
  public ProductionReadinessCheck checkAuthzenAuthorization(
      PolarisAuthorizerFactory authorizerFactory) {
    if (authorizerFactory instanceof AuthzenPolarisAuthorizerFactory authzenFactory) {
      AuthzenAuthorizationConfig config = authzenFactory.getConfig();

      List<Error> errors = new ArrayList<>();

      errors.add(
          Error.of(
              "AuthZEN authorization is currently a preview feature and is not a stable release. Breaking changes may be introduced in future versions. Use with caution in production environments.",
              "polaris.authorization.type"));

      if (!config.http().verifySsl()) {
        errors.add(
            Error.ofSevere(
                "SSL certificate verification is disabled for AuthZEN PDP communication. This exposes the service to man-in-the-middle attacks and other severe security risks.",
                "polaris.authorization.authzen.http.verify-ssl"));
      }

      if (config.auth().type() != AuthzenAuthorizationConfig.AuthenticationType.NONE
          && isPlaintext(config.pdpUri())) {
        errors.add(
            Error.ofSevere(
                "The AuthZEN PDP is addressed over plain HTTP while credentials are sent to it. The bearer token is exposed to anyone who can observe the network.",
                "polaris.authorization.authzen.pdp-uri"));
      }

      if (config.auth().type() == AuthzenAuthorizationConfig.AuthenticationType.CLIENT_CREDENTIALS
          && config.auth().clientCredentials().isPresent()
          && isPlaintext(Optional.of(config.auth().clientCredentials().get().tokenEndpoint()))) {
        errors.add(
            Error.ofSevere(
                "The OAuth2 token endpoint is addressed over plain HTTP. The client secret is exposed to anyone who can observe the network.",
                "polaris.authorization.authzen.auth.client-credentials.token-endpoint"));
      }

      return ProductionReadinessCheck.of(errors);
    }
    return ProductionReadinessCheck.OK;
  }

  private static boolean isPlaintext(Optional<URI> uri) {
    return uri.map(URI::getScheme).filter("http"::equalsIgnoreCase).isPresent();
  }
}
