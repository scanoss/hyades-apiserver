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

public class CryptoCertificateCelPolicyScriptSourceBuilder implements CelPolicyScriptSourceBuilder {

    @Override
    public String apply(final PolicyCondition policyCondition) {
        final String value = escapeQuotes(policyCondition.getValue());
        return switch (policyCondition.getSubject()) {
            case CRYPTO_CERTIFICATE_EXPIRY -> buildExpiryScript(policyCondition, value);
            case CRYPTO_CERTIFICATE_ALGORITHM -> buildAlgorithmScript(policyCondition, value);
            default -> null;
        };
    }

    private static String buildExpiryScript(final PolicyCondition condition, final String value) {
        // Certificate expiry: compare not_valid_after against now.
        // Value is expected to be a duration like "P30D" (30 days), but for simple operators
        // we compare not_valid_after < now (expired).
        return switch (condition.getOperator()) {
            case NUMERIC_LESS_THAN -> """
                    crypto_asset.certificate.not_valid_after < now
                    """;
            case NUMERIC_GREATER_THAN -> """
                    crypto_asset.certificate.not_valid_after > now
                    """;
            case IS -> """
                    crypto_asset.certificate.not_valid_after < now
                    """;
            default -> null;
        };
    }

    private static String buildAlgorithmScript(final PolicyCondition condition, final String value) {
        return switch (condition.getOperator()) {
            case IS -> """
                    crypto_asset.certificate.signature_algorithm_ref == "%s"
                    """.formatted(value);
            case IS_NOT -> """
                    crypto_asset.certificate.signature_algorithm_ref != "%s"
                    """.formatted(value);
            case MATCHES -> """
                    crypto_asset.certificate.signature_algorithm_ref.matches("%s")
                    """.formatted(value);
            default -> null;
        };
    }

}
