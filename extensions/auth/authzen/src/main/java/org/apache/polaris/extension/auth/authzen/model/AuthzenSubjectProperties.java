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

/** The free-form {@code properties} object of an AuthZEN subject, as Polaris populates it. */
@PolarisImmutable
@JsonSerialize(as = ImmutableAuthzenSubjectProperties.class)
@JsonDeserialize(as = ImmutableAuthzenSubjectProperties.class)
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public interface AuthzenSubjectProperties {
  /** The activated principal roles of the requesting principal. */
  @JsonInclude(JsonInclude.Include.NON_EMPTY)
  List<String> roles();

  /**
   * The realm identifier of the request.
   *
   * <p>This lets a single PDP policy isolate principals that share a name across realms.
   */
  String realm();
}
