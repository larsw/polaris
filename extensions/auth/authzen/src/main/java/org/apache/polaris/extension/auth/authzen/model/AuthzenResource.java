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
package org.apache.polaris.extension.auth.authzen.model;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.apache.polaris.immutables.PolarisImmutable;

/** The AuthZEN {@code Resource} object: what is being acted upon. */
@PolarisImmutable
@JsonSerialize(as = ImmutableAuthzenResource.class)
@JsonDeserialize(as = ImmutableAuthzenResource.class)
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public interface AuthzenResource {
  /** The resource type, derived from the Polaris entity type of the resource. */
  String type();

  /** The resource identifier, as selected by the configured resource id format. */
  String id();

  /** Structured Polaris detail that does not fit into {@link #type()} and {@link #id()}. */
  AuthzenResourceProperties properties();
}
