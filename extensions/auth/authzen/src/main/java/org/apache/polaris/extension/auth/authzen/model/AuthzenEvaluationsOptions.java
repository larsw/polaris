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

/** The {@code options} object of a batched Access Evaluations request. */
@PolarisImmutable
@JsonSerialize(as = ImmutableAuthzenEvaluationsOptions.class)
@JsonDeserialize(as = ImmutableAuthzenEvaluationsOptions.class)
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public interface AuthzenEvaluationsOptions {
  /**
   * Evaluation semantics requested from the PDP.
   *
   * <p>Polaris AND-combines the intents of an authorization request, so it asks the PDP to stop at
   * the first deny. A PDP that ignores this option and evaluates everything still produces the same
   * overall decision.
   */
  String evaluationsSemantic();
}
