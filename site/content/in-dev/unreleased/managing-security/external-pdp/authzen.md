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
title: AuthZEN Integration
linkTitle: AuthZEN
type: docs
weight: 200
---

{{< alert warning "Preview Feature" >}}
**AuthZEN integration is currently a preview feature** and may undergo breaking changes in future versions. Use with caution in production environments.
{{< /alert >}}

This page describes how to integrate Apache Polaris with a Policy Decision Point that implements the [OpenID AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html).

## Overview

AuthZEN is a vendor-neutral protocol between a Policy Enforcement Point (PEP) and a Policy Decision Point (PDP). Polaris acts as the PEP: it describes who is asking, what they want to do and what they want to do it to, and the PDP answers `true` or `false`.

Unlike the [OPA integration]({{< relref "opa.md" >}}), which speaks OPA's own data-query API and expects Rego policies, the AuthZEN integration does not know or care which policy engine sits behind the endpoint. Any conforming PDP works, including:

- [Keycloak](https://www.keycloak.org/securing-apps/authzen-authorization) 26.7 and later, behind its experimental `authzen` feature
- [Cerbos](https://www.cerbos.dev/), [Topaz](https://www.topaz.sh/), and the other implementations listed in the [AuthZEN interop reports](https://authzen-interop.net/)

Key benefits:

- **No lock-in to one policy engine**: the wire protocol is standardised, so the PDP can be replaced without touching Polaris
- **One round-trip per request**: several authorization checks are batched into a single call
- **Reuse of an existing PDP**: organisations that already run an AuthZEN PDP for their other services can put Polaris behind the same policies

## Prerequisites

1. **An AuthZEN PDP** reachable from Polaris
2. **Policies** in that PDP covering the Polaris operations your users need
3. **Credentials** for the PDP, if it requires authentication

## Quick Start with Keycloak

Keycloak exposes AuthZEN endpoints when started with its experimental `authzen` feature.

### 1. Start Keycloak with the feature enabled

```bash
docker run -d --name keycloak -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.7.4 \
  start-dev --features=authzen
```

Confirm the endpoints are advertised:

```bash
curl -s http://localhost:8080/realms/master/.well-known/authzen-configuration
```

```json
{
  "policy_decision_point": "http://localhost:8080/realms/master",
  "access_evaluation_endpoint": "http://localhost:8080/realms/master/authzen/access/v1/evaluation",
  "access_evaluations_endpoint": "http://localhost:8080/realms/master/authzen/access/v1/evaluations"
}
```

### 2. Create the PDP client

Keycloak requires the caller to present an access token issued to a client with authorization services enabled. Create one (here via `kcadm.sh`):

```bash
CLIENT_ID=$(kcadm.sh create clients -r master \
  -s clientId=polaris-pdp \
  -s enabled=true \
  -s secret=polaris-pdp-secret \
  -s serviceAccountsEnabled=true \
  -s authorizationServicesEnabled=true \
  -i)
```

### 3. Register scopes, resources and permissions

Keycloak matches `action.name` against authorization **scopes** and `resource.id` against **resources that were registered in advance**. Create one scope per Polaris operation you want to reason about, and one resource per Polaris entity type:

```bash
kcadm.sh create "clients/$CLIENT_ID/authz/resource-server/scope" -r master -s name=LIST_CATALOGS
kcadm.sh create "clients/$CLIENT_ID/authz/resource-server/scope" -r master -s name=CREATE_CATALOG
kcadm.sh create "clients/$CLIENT_ID/authz/resource-server/scope" -r master -s name=LOAD_TABLE
# ... one per operation you want to allow

# One resource per Polaris entity type, each carrying every scope. Which entity type an
# operation arrives on is a Polaris detail -- CREATE_CATALOG, for instance, is realm-scoped and
# arrives on ROOT, not on CATALOG -- so attaching all scopes to all resources and letting the
# permissions decide is both simpler and less surprising.
for TYPE in ROOT PRINCIPAL PRINCIPAL_ROLE CATALOG CATALOG_ROLE NAMESPACE TABLE_LIKE TASK FILE POLICY SEMANTIC_MODEL; do
  kcadm.sh create "clients/$CLIENT_ID/authz/resource-server/resource" -r master \
    -s name=$TYPE -s type=polaris:$TYPE \
    -s 'scopes=[{"name":"LIST_CATALOGS"},{"name":"CREATE_CATALOG"},{"name":"LOAD_TABLE"}]'
done

kcadm.sh create "clients/$CLIENT_ID/authz/resource-server/policy/user" -r master \
  -s name=polaris-operators -s 'users=["alice"]'

kcadm.sh create "clients/$CLIENT_ID/authz/resource-server/permission/scope" -r master \
  -s name=polaris-operator-permission \
  -s decisionStrategy=AFFIRMATIVE \
  -s 'resources=["ROOT","PRINCIPAL","PRINCIPAL_ROLE","CATALOG","CATALOG_ROLE","NAMESPACE","TABLE_LIKE","TASK","FILE","POLICY","SEMANTIC_MODEL"]' \
  -s 'scopes=["LIST_CATALOGS","CREATE_CATALOG","LOAD_TABLE"]' \
  -s 'policies=["polaris-operators"]'
```

The Keycloak **user** names must match the Polaris **principal** names. A Polaris principal with no matching Keycloak user is denied.

{{< alert warning "Set the resource server to AFFIRMATIVE" >}}
Keycloak defaults a resource server to the `UNANIMOUS` decision strategy, which requires *every* permission covering a (resource, scope) pair to grant access. As soon as you model more than one role -- an operator permission and a read-only permission, say -- the two contradict each other on the scopes they share, and everyone is denied.

Set the resource server itself to `AFFIRMATIVE`, so that access is granted when any permission grants it:

```bash
kcadm.sh update "clients/$CLIENT_ID/authz/resource-server" -r master -s decisionStrategy=AFFIRMATIVE
```
{{< /alert >}}

### 4. Configure Polaris

```properties
polaris.authorization.type=authzen

# The PDP base URI; endpoints are discovered from its .well-known document
polaris.authorization.authzen.pdp-uri=http://localhost:8080/realms/master

# Keycloak issues short-lived tokens, so Polaris fetches and refreshes its own
polaris.authorization.authzen.auth.type=client-credentials
polaris.authorization.authzen.auth.client-credentials.token-endpoint=\
  http://localhost:8080/realms/master/protocol/openid-connect/token
polaris.authorization.authzen.auth.client-credentials.client-id=polaris-pdp
polaris.authorization.authzen.auth.client-credentials.client-secret=polaris-pdp-secret

# Keycloak-specific payload shaping, see "Adapting the payload to your PDP"
polaris.authorization.authzen.mapping.subject-id-prefix=username:
polaris.authorization.authzen.mapping.resource-type-prefix=polaris:
polaris.authorization.authzen.mapping.resource-id-format=type
```

### 5. Restart Polaris

Restart the Polaris service to apply the configuration.

## Configuration Reference

### Basic Configuration

| Property | Required | Default | Description |
|----------|----------|---------|-------------|
| `polaris.authorization.type` | Yes | `internal` | Set to `authzen` to enable AuthZEN authorization |
| `polaris.authorization.authzen.pdp-uri` | Yes* | - | Base URI of the PDP. Endpoints are discovered from `<pdp-uri>/.well-known/authzen-configuration`. (*required unless the endpoints are set explicitly) |
| `polaris.authorization.authzen.access-evaluation-endpoint` | No | discovered | Explicit Access Evaluation endpoint; bypasses discovery |
| `polaris.authorization.authzen.access-evaluations-endpoint` | No | discovered | Explicit Access Evaluations (batch) endpoint; bypasses discovery |
| `polaris.authorization.authzen.use-batch-endpoint` | No | `true` | Batch the intents of one request into a single call. When `false`, or when the PDP advertises no batch endpoint, Polaris sends one call per intent |

### Payload Mapping

| Property | Required | Default | Description |
|----------|----------|---------|-------------|
| `polaris.authorization.authzen.mapping.subject-type` | No | `user` | Value sent as `subject.type` |
| `polaris.authorization.authzen.mapping.subject-id-prefix` | No | - | Prefix prepended to the principal name in `subject.id`, e.g. `username:` for Keycloak |
| `polaris.authorization.authzen.mapping.resource-type-prefix` | No | - | Prefix prepended to the Polaris entity type in `resource.type`, e.g. `polaris:` |
| `polaris.authorization.authzen.mapping.resource-id-format` | No | `path` | `path`, `name` or `type`. See below |
| `polaris.authorization.authzen.mapping.resource-id-separator` | No | `/` | Separator used to join path segments when the format is `path` |
| `polaris.authorization.authzen.mapping.action-name-case` | No | `as-is` | `as-is` or `lower` |
| `polaris.authorization.authzen.mapping.root-resource-type` | No | `ROOT` | `resource.type` used for realm-scoped operations |

### HTTP Configuration

| Property | Required | Default | Description |
|----------|----------|---------|-------------|
| `polaris.authorization.authzen.http.timeout` | No | `PT2S` | HTTP request timeout (ISO-8601 duration) |
| `polaris.authorization.authzen.http.verify-ssl` | No | `true` | Whether to verify SSL certificates |
| `polaris.authorization.authzen.http.trust-store-path` | No | - | Path to the trust store containing CA certificates |
| `polaris.authorization.authzen.http.trust-store-password` | No | - | Password for the trust store |

### Authentication Configuration

Three modes are supported.

#### No Authentication (default)

```properties
polaris.authorization.authzen.auth.type=none
```

#### OAuth2 Client Credentials

Polaris fetches an access token from the token endpoint and refreshes it before it expires. This is the mode to use with Keycloak.

```properties
polaris.authorization.authzen.auth.type=client-credentials
polaris.authorization.authzen.auth.client-credentials.token-endpoint=https://idp.example.com/realms/demo/protocol/openid-connect/token
polaris.authorization.authzen.auth.client-credentials.client-id=polaris-pdp
polaris.authorization.authzen.auth.client-credentials.client-secret=...
```

| Property | Required | Default | Description |
|----------|----------|---------|-------------|
| `...auth.client-credentials.token-endpoint` | Yes | - | OAuth2 token endpoint |
| `...auth.client-credentials.client-id` | Yes | - | OAuth2 client id |
| `...auth.client-credentials.client-secret` | Yes | - | OAuth2 client secret |
| `...auth.client-credentials.scope` | No | - | Space-delimited scope string to request |
| `...auth.client-credentials.expiration-buffer` | No | `PT1M` | How long before expiry the token is refreshed |
| `...auth.client-credentials.refresh-interval` | No | `PT5M` | Refresh interval used when the token endpoint reports no lifetime |
| `...auth.client-credentials.initial-token-wait` | No | `PT5S` | How long a request waits for the first token |
| `...auth.client-credentials.refresh-retry-interval` | No | `PT1S` | Delay before retrying a failed token fetch |

#### Bearer Token

A static token, or a token read from a file and reloaded as it changes. Identical in behaviour to the OPA integration's bearer support.

```properties
polaris.authorization.authzen.auth.type=bearer
polaris.authorization.authzen.auth.bearer.static-token.value=your-secret-token
```

```properties
polaris.authorization.authzen.auth.type=bearer
polaris.authorization.authzen.auth.bearer.file-based.path=/var/secrets/token.txt
polaris.authorization.authzen.auth.bearer.file-based.jwt-expiration-refresh=true
polaris.authorization.authzen.auth.bearer.file-based.jwt-expiration-buffer=PT1M
```

| Property | Required | Default | Description |
|----------|----------|---------|-------------|
| `...auth.bearer.static-token.value` | Yes* | - | The bearer token value (*when using a static token) |
| `...auth.bearer.file-based.path` | Yes* | - | Path to the file containing the bearer token (*when using a file-based token) |
| `...auth.bearer.file-based.refresh-interval` | No | `PT5M` | How often to re-read the file |
| `...auth.bearer.file-based.jwt-expiration-refresh` | No | `true` | Refresh based on the JWT `exp` claim when the token is a JWT |
| `...auth.bearer.file-based.jwt-expiration-buffer` | No | `PT1M` | Buffer before JWT expiration |

## The Request Polaris Sends

### Single evaluation

For a request with one intent, Polaris posts to the Access Evaluation endpoint:

```json
{
  "subject": {
    "type": "user",
    "id": "alice",
    "properties": {
      "roles": ["analyst"],
      "realm": "POLARIS"
    }
  },
  "action": {
    "name": "LOAD_TABLE_WITH_READ_DELEGATION"
  },
  "resource": {
    "type": "TABLE_LIKE",
    "id": "my_catalog/sales/orders",
    "properties": {
      "name": "orders",
      "parents": [
        {"type": "CATALOG", "name": "my_catalog"},
        {"type": "NAMESPACE", "name": "sales"}
      ]
    }
  },
  "context": {
    "request_id": "8a1f...",
    "realm": "POLARIS"
  }
}
```

The PDP answers:

```json
{"decision": true}
```

Polaris also sends the `request_id` as an `X-Request-ID` header, so PDP logs can be correlated with Polaris logs.

### Batched evaluations

A Polaris authorization request may carry several intents, which are AND-combined. Polaris sends them in one call, asking the PDP to stop at the first denial:

```json
{
  "subject": { "type": "user", "id": "alice", "properties": {"roles": ["analyst"], "realm": "POLARIS"} },
  "context": { "request_id": "8a1f...", "realm": "POLARIS" },
  "options": { "evaluations_semantic": "deny_on_first_deny" },
  "evaluations": [
    {"action": {"name": "UPDATE_TABLE"}, "resource": {"type": "TABLE_LIKE", "id": "my_catalog/sales/orders", "properties": {"name": "orders", "parents": [...]}}},
    {"action": {"name": "UPDATE_TABLE"}, "resource": {"type": "TABLE_LIKE", "id": "my_catalog/sales/returns", "properties": {"name": "returns", "parents": [...]}}}
  ]
}
```

```json
{"evaluations": [{"decision": true}, {"decision": true}]}
```

Polaris **fails closed** when it cannot line the answers up with the questions:

- a `false` at any position denies the whole request
- a short array is accepted only when it ends in a deny, which is what `deny_on_first_deny` produces. A short array of permits means intents went unevaluated, and is denied
- more answers than questions, a missing `evaluations` array, a missing or non-boolean `decision`, or any non-`200` response is denied

### Field reference

| Field | Value |
|-------|-------|
| `subject.type` | `mapping.subject-type`, `user` by default |
| `subject.id` | `mapping.subject-id-prefix` + the Polaris principal name |
| `subject.properties.roles` | The principal's activated principal roles. Omitted when empty |
| `subject.properties.realm` | The realm identifier, so one policy can isolate realms that share principal names |
| `action.name` | The [`PolarisAuthorizableOperation`](https://github.com/apache/polaris/blob/main/polaris-core/src/main/java/org/apache/polaris/core/auth/PolarisAuthorizableOperation.java) value, cased per `mapping.action-name-case` |
| `resource.type` | `mapping.resource-type-prefix` + the Polaris entity type (`CATALOG`, `NAMESPACE`, `TABLE_LIKE`, `PRINCIPAL`, ...) |
| `resource.id` | Per `mapping.resource-id-format` |
| `resource.properties.name` | The unqualified resource name |
| `resource.properties.parents` | The parent path, from the furthest parent to the immediate one. Omitted when empty |
| `resource.properties.secondaries` | The second resource of a two-sided operation. Omitted when empty |
| `context.request_id` | Correlation id, also sent as the `X-Request-ID` header |
| `context.realm` | The realm identifier |

### Two conventions worth knowing

**Realm-scoped operations.** Some operations act on no particular entity -- `LIST_CATALOGS`, `LIST_PRINCIPALS`, and root-level grants. AuthZEN requires a resource, so Polaris sends a synthetic one whose type is `mapping.root-resource-type` (`ROOT` by default). Its id is the realm identifier, or the root type itself when `resource-id-format=type`.

**Two-sided operations.** `RENAME_TABLE`, privilege grants, role assignments and policy attachments name two resources. AuthZEN evaluates one resource at a time, so the primary resource goes in `resource` and the second one in `resource.properties.secondaries`. A policy that must authorize both sides has to read `secondaries` -- a PDP that ignores it authorizes only the primary resource.

## Adapting the Payload to Your PDP

The defaults produce a self-describing payload. PDPs differ in what strings they match on, which is what `mapping.*` is for.

### `resource-id-format`

| Value | `resource.id` for a table | When to use it |
|-------|---------------------------|----------------|
| `path` (default) | `my_catalog/sales/orders` | PDPs that evaluate rules over the id, such as OPA-backed or Cedar-backed PDPs |
| `name` | `orders` | PDPs that match on the leaf name alone |
| `type` | `TABLE_LIKE` | PDPs that resolve ids against resources registered in advance |

{{< alert warning "Keycloak requires `resource-id-format=type`" >}}
Keycloak resolves `resource.id` against authorization-services resources that were registered up front, and denies anything it cannot find. Catalogs, namespaces and tables are created at runtime, so their names can never be registered in advance and every request would be denied.

Setting `resource-id-format=type` keeps the id within the finite set of Polaris entity types, so one registered Keycloak resource per type covers everything. The consequence is that with Keycloak, decisions are made per *entity type* and operation, not per individual table. The instance is still described in `resource.properties`, but Keycloak's policy model does not read it.
{{< /alert >}}

### `resource-id-separator`

Polaris entity names may themselves contain `/` or `.`, so a joined path is not guaranteed to be unambiguous. A policy that needs an exact path should read `resource.properties.parents`, which is structured. If your PDP needs an unambiguous single string, set the separator to a character that cannot appear in a Polaris name, for example the ASCII unit separator:

```properties
polaris.authorization.authzen.mapping.resource-id-separator=\u001F
```

## Policy Considerations

{{< alert warning "Important Policy Considerations" >}}
**Deny by default.** Polaris delegates every authorization decision to the PDP; its own role-based grants are not consulted. Operations your policy does not explicitly allow should be denied, so that operations added in a future Polaris version are denied until you decide otherwise.

**Internal-only operations.** Operations such as `CREATE_POLICY` and the various `ADD_*_GRANT_TO_CATALOG_ROLE` manage Polaris's internal privilege system. Denying them in the PDP keeps privilege management inside Polaris's native authorization system.
{{< /alert >}}

## Troubleshooting

**Everything is denied.** Check that `resource.id` is a value the PDP can resolve -- with Keycloak this almost always means `resource-id-format=type` plus registered resources, and a resource server set to `AFFIRMATIVE`. Polaris logs each denial, and the full request and response payloads, at `DEBUG` on the `org.apache.polaris.extension.auth.authzen` category:

```properties
quarkus.log.category."org.apache.polaris.extension.auth.authzen".level=DEBUG
```

Comparing the logged payload against what the PDP is configured to match on usually shows the problem immediately.

**Startup logs "Could not resolve AuthZEN PDP endpoints".** Discovery failed but did not fail startup; it is retried on the first authorization request. Check `pdp-uri` and that the PDP is reachable, or set the endpoints explicitly.

**`401` from the PDP.** Polaris logs the status and treats it as a denial. With Keycloak, confirm the client has authorization services enabled and that the client credentials are correct.

## Additional Resources

- [AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html)
- [AuthZEN interop reports](https://authzen-interop.net/)
- [Keycloak AuthZEN authorization](https://www.keycloak.org/securing-apps/authzen-authorization)
- [Keycloak AuthZEN playground](https://github.com/keycloak/keycloak-playground/tree/main/authzen)
