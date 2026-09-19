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

/**
 * Request model for the OpenID AuthZEN Authorization API 1.0.
 *
 * <p>These immutable types are the single source of truth for what Polaris sends to an AuthZEN
 * Policy Decision Point. Responses are parsed with Jackson's tree API rather than modelled here, so
 * that a PDP returning additional fields -- which the specification explicitly permits -- does not
 * break deserialization.
 *
 * <h2>Model structure</h2>
 *
 * <ul>
 *   <li>{@link org.apache.polaris.extension.auth.authzen.model.AuthzenEvaluationRequest} - a single
 *       access evaluation
 *   <li>{@link org.apache.polaris.extension.auth.authzen.model.AuthzenEvaluationsRequest} - a
 *       batched access evaluation, one {@link
 *       org.apache.polaris.extension.auth.authzen.model.AuthzenEvaluationItem} per Polaris intent
 *   <li>{@link org.apache.polaris.extension.auth.authzen.model.AuthzenSubject} - the requesting
 *       principal
 *   <li>{@link org.apache.polaris.extension.auth.authzen.model.AuthzenAction} - the Polaris
 *       operation
 *   <li>{@link org.apache.polaris.extension.auth.authzen.model.AuthzenResource} - the resource
 *       being accessed, with Polaris's hierarchical detail in {@link
 *       org.apache.polaris.extension.auth.authzen.model.AuthzenResourceProperties}
 *   <li>{@link org.apache.polaris.extension.auth.authzen.model.AuthzenContext} - request metadata
 * </ul>
 *
 * @see <a href="https://openid.net/specs/authorization-api-1_0.html">AuthZEN Authorization API
 *     1.0</a>
 */
package org.apache.polaris.extension.auth.authzen.model;
