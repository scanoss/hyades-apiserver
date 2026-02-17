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

public class CryptoQuantumCelPolicyScriptSourceBuilder implements CelPolicyScriptSourceBuilder {

    @Override
    public String apply(final PolicyCondition policyCondition) {
        final String value = policyCondition.getValue();
        final String field = switch (policyCondition.getSubject()) {
            case CRYPTO_CLASSICAL_STRENGTH -> "crypto_asset.algorithm.classical_security_level";
            default -> "crypto_asset.algorithm.nist_quantum_security_level"; // CRYPTO_QUANTUM_SECURITY
        };
        return switch (policyCondition.getOperator()) {
            case NUMERIC_GREATER_THAN -> """
                    %s > %s
                    """.formatted(field, value);
            case NUMERIC_LESS_THAN -> """
                    %s < %s
                    """.formatted(field, value);
            case NUMERIC_EQUAL -> """
                    %s == %s
                    """.formatted(field, value);
            case IS -> """
                    %s == %s
                    """.formatted(field, value);
            case IS_NOT -> """
                    %s != %s
                    """.formatted(field, value);
            default -> null;
        };
    }

}
