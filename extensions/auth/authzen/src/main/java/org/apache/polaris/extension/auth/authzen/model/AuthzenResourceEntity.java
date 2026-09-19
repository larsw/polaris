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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import java.util.List;
import org.apache.polaris.immutables.PolarisImmutable;

/**
 * A single Polaris entity carried inside {@code resource.properties}.
 *
 * <p>AuthZEN's {@code resource} object only has room for one {@code type}/{@code id} pair, so the
 * hierarchical detail Polaris knows about -- parent paths and the secondary resource of two-sided
 * operations such as {@code RENAME_TABLE} -- is carried as structured properties instead.
 */
@PolarisImmutable
@JsonSerialize(as = ImmutableAuthzenResourceEntity.class)
@JsonDeserialize(as = ImmutableAuthzenResourceEntity.class)
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public interface AuthzenResourceEntity {
  /**
   * The Polaris entity type, for example {@code CATALOG}, {@code NAMESPACE}, {@code TABLE_LIKE}.
   */
  String type();

  /** The entity name. */
  String name();

  /** The hierarchical path of parent entities, from the furthest parent to the immediate one. */
  @JsonInclude(JsonInclude.Include.NON_EMPTY)
  List<AuthzenResourceEntity> parents();
}
