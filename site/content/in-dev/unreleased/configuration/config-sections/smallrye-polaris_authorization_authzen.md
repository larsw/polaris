---
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#
title: smallrye-polaris_authorization_authzen
build:
  list: never
  render: never
---

Configuration for authorization against an AuthZEN-compliant Policy Decision Point. 

Preview Feature: AuthZEN authorization is currently a preview feature and is  not a stable release. It may undergo breaking changes in future versions. Use with caution in  production environments.

| Property | Default Value | Type | Description |
|----------|---------------|------|-------------|
| `polaris.authorization.authzen.pdp-uri` |  | `uri` | Base URI of the PDP, used to discover the evaluation endpoints via its `.well-known/authzen-configuration` document.  For Keycloak this is the realm URI, for example  `https://keycloak.example.com/realms/demo`. |
| `polaris.authorization.authzen.access-evaluation-endpoint` |  | `uri` | Explicit URI of the Access Evaluation endpoint. Set this to bypass discovery; it takes  precedence over the endpoint advertised by the PDP metadata.  |
| `polaris.authorization.authzen.access-evaluations-endpoint` |  | `uri` | Explicit URI of the Access Evaluations (batch) endpoint. Set this to bypass discovery; it takes  precedence over the endpoint advertised by the PDP metadata.  |
| `polaris.authorization.authzen.use-batch-endpoint` | `true` | `boolean` | Whether to batch the intents of one authorization request into a single Access Evaluations  call.  When disabled, or when the PDP advertises no batch endpoint, Polaris falls back to one  Access Evaluation call per intent.  |
| `polaris.authorization.authzen.mapping.subject-type` | `user` | `string` | The value sent as `subject.type`  |
| `polaris.authorization.authzen.mapping.subject-id-prefix` |  | `string` | A prefix prepended to the principal name when building `subject.id`  |
| `polaris.authorization.authzen.mapping.resource-type-prefix` |  | `string` | A prefix prepended to the Polaris entity type when building `resource.type`  |
| `polaris.authorization.authzen.mapping.resource-id-format` | `path` | `enum (PATH, NAME, TYPE)` | How `resource.id` is derived from the resource path   |
| `polaris.authorization.authzen.mapping.resource-id-separator` | `/` | `string` | The separator used to join path segments when `resource-id-format` is `path`. Polaris entity names may themselves contain this separator, so a policy that needs an  unambiguous path should read `resource.properties.parents` instead.  |
| `polaris.authorization.authzen.mapping.action-name-case` | `as-is` | `enum (AS_IS, LOWER)` | How the Polaris operation name is cased before being sent as `action.name`  |
| `polaris.authorization.authzen.mapping.root-resource-type` | `ROOT` | `string` | The `resource.type` used for operations that act on the realm as a whole rather than on  a specific entity, such as `LIST_CATALOGS`. The realm identifier is sent as the `resource.id` . |
| `polaris.authorization.authzen.auth.type` | `none` | `enum (NONE, BEARER, CLIENT_CREDENTIALS)` | Type of authentication  |
| `polaris.authorization.authzen.auth.bearer.static-token.value` |  | `string` | Static bearer token value  |
| `polaris.authorization.authzen.auth.bearer.file-based.path` |  | `path` | Path to file containing bearer token  |
| `polaris.authorization.authzen.auth.bearer.file-based.refresh-interval` |  | `duration` | How often to refresh file-based bearer tokens (defaults to 5 minutes if not specified)  |
| `polaris.authorization.authzen.auth.bearer.file-based.jwt-expiration-refresh` |  | `boolean` | Whether to automatically detect JWT tokens and use their 'exp' field for refresh timing. If  true and the token is a valid JWT with an 'exp' claim, the token will be refreshed based on  the expiration time minus the buffer, rather than the fixed refresh interval. Defaults to  true if not specified.  |
| `polaris.authorization.authzen.auth.bearer.file-based.jwt-expiration-buffer` |  | `duration` | Buffer time before JWT expiration to refresh the token. Only used when jwtExpirationRefresh  is true and the token is a valid JWT. Defaults to 1 minute if not specified.  |
| `polaris.authorization.authzen.auth.bearer.file-based.initial-token-wait` |  | `duration` | How long to wait for the first token load before failing a request. Defaults to 5 seconds. |
| `polaris.authorization.authzen.auth.bearer.file-based.refresh-retry-interval` |  | `duration` | How long to wait before retrying after a failed token refresh. Defaults to 1 second. |
| `polaris.authorization.authzen.auth.client-credentials.token-endpoint` |  | `uri` | The OAuth2 token endpoint to request access tokens from  |
| `polaris.authorization.authzen.auth.client-credentials.client-id` |  | `string` | The OAuth2 client id  |
| `polaris.authorization.authzen.auth.client-credentials.client-secret` |  | `string` | The OAuth2 client secret  |
| `polaris.authorization.authzen.auth.client-credentials.scope` |  | `string` | An optional space-delimited scope string to request  |
| `polaris.authorization.authzen.auth.client-credentials.expiration-buffer` |  | `duration` | How long before a token expires it is refreshed. Defaults to 1 minute if not specified. |
| `polaris.authorization.authzen.auth.client-credentials.refresh-interval` |  | `duration` | How often to refresh the token when the token endpoint does not report a lifetime. Defaults  to 5 minutes if not specified.  |
| `polaris.authorization.authzen.auth.client-credentials.initial-token-wait` |  | `duration` | How long to wait for the first token to be fetched before failing a request. Defaults to 5  seconds.  |
| `polaris.authorization.authzen.auth.client-credentials.refresh-retry-interval` |  | `duration` | How long to wait before retrying after a failed token fetch. Defaults to 1 second. |
| `polaris.authorization.authzen.http.timeout` | `PT2S` | `duration` |  |
| `polaris.authorization.authzen.http.verify-ssl` | `true` | `boolean` |  |
| `polaris.authorization.authzen.http.trust-store-path` |  | `path` |  |
| `polaris.authorization.authzen.http.trust-store-password` |  | `string` |  |
