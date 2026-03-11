/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.policy.cel.compat;

import org.dependencytrack.model.PolicyCondition;

import static org.dependencytrack.policy.cel.compat.CelPolicyScriptSourceBuilder.escapeQuotes;

public class CryptoAlgorithmCelPolicyScriptSourceBuilder implements CelPolicyScriptSourceBuilder {

    @Override
    public String apply(final PolicyCondition policyCondition) {
        final String value = escapeQuotes(policyCondition.getValue());
        final String field = switch (policyCondition.getSubject()) {
            case CRYPTO_ALGORITHM_PRIMITIVE -> "crypto_asset.algorithm.primitive";
            case CRYPTO_ALGORITHM_PARAMETER_SET -> "crypto_asset.algorithm.parameter_set_identifier";
            default -> "crypto_asset.name"; // CRYPTO_ALGORITHM_NAME
        };
        return switch (policyCondition.getOperator()) {
            case IS -> """
                    %s == "%s"
                    """.formatted(field, value);
            case IS_NOT -> """
                    %s != "%s"
                    """.formatted(field, value);
            case MATCHES -> """
                    %s.matches("%s")
                    """.formatted(field, value);
            default -> null;
        };
    }

}
