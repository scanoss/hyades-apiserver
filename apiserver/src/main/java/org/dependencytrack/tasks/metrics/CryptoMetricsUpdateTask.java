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
package org.dependencytrack.tasks.metrics;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import org.dependencytrack.event.CryptoMetricsUpdateEvent;
import org.dependencytrack.model.CryptoAsset;
import org.dependencytrack.model.CryptoAssetMetrics;
import org.dependencytrack.model.CryptoAssetType;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.QueryManager;
import org.slf4j.MDC;

import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_UUID;

/**
 * A {@link Subscriber} task that updates crypto asset metrics for a project.
 */
public class CryptoMetricsUpdateTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(CryptoMetricsUpdateTask.class);

    @Override
    public void inform(final Event e) {
        if (e instanceof final CryptoMetricsUpdateEvent event) {
            try (var ignoredMdcProjectUuid = MDC.putCloseable(MDC_PROJECT_UUID, event.getUuid().toString())) {
                updateMetrics(event.getUuid());
            }
        }
    }

    private void updateMetrics(final UUID projectUuid) {
        LOGGER.debug("Executing crypto metrics update for project %s".formatted(projectUuid));
        try (final var qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, projectUuid);
            if (project == null) {
                LOGGER.warn("Project %s not found, skipping crypto metrics update".formatted(projectUuid));
                return;
            }

            final List<CryptoAsset> assets = qm.getAllCryptoAssetsList(project);

            int totalAssets = assets.size();
            int algorithmCount = 0;
            int protocolCount = 0;
            int certificateCount = 0;
            int relatedMaterialCount = 0;
            int quantumSafe = 0;
            int quantumVulnerable = 0;
            int quantumUnknown = 0;
            int classicalStrengthHigh = 0;
            int classicalStrengthMedium = 0;
            int classicalStrengthLow = 0;
            int expiredCertificates = 0;
            int expiringCertificates = 0;
            int policyViolations = 0;

            final Date now = new Date();
            final long thirtyDaysMs = 30L * 24 * 60 * 60 * 1000;

            for (final CryptoAsset asset : assets) {
                switch (asset.getAssetType()) {
                    case ALGORITHM -> {
                        algorithmCount++;
                        if (asset.getAlgorithm() != null) {
                            final Integer nistLevel = asset.getAlgorithm().getNistQuantumSecurityLevel();
                            if (nistLevel != null) {
                                if (nistLevel > 0) {
                                    quantumSafe++;
                                } else {
                                    quantumVulnerable++;
                                }
                            } else {
                                quantumUnknown++;
                            }
                            final Integer classicalLevel = asset.getAlgorithm().getClassicalSecurityLevel();
                            if (classicalLevel != null) {
                                if (classicalLevel >= 192) {
                                    classicalStrengthHigh++;
                                } else if (classicalLevel >= 128) {
                                    classicalStrengthMedium++;
                                } else {
                                    classicalStrengthLow++;
                                }
                            }
                        }
                    }
                    case PROTOCOL -> protocolCount++;
                    case CERTIFICATE -> {
                        certificateCount++;
                        if (asset.getCertificate() != null && asset.getCertificate().getNotValidAfter() != null) {
                            final Date expiry = asset.getCertificate().getNotValidAfter();
                            if (expiry.before(now)) {
                                expiredCertificates++;
                            } else if (expiry.getTime() - now.getTime() <= thirtyDaysMs) {
                                expiringCertificates++;
                            }
                        }
                    }
                    case RELATED_CRYPTO_MATERIAL -> relatedMaterialCount++;
                }
            }

            final CryptoAssetMetrics metrics = new CryptoAssetMetrics();
            metrics.setProjectId(project.getId());
            metrics.setTotalAssets(totalAssets);
            metrics.setAlgorithmCount(algorithmCount);
            metrics.setProtocolCount(protocolCount);
            metrics.setCertificateCount(certificateCount);
            metrics.setRelatedMaterialCount(relatedMaterialCount);
            metrics.setQuantumSafe(quantumSafe);
            metrics.setQuantumVulnerable(quantumVulnerable);
            metrics.setQuantumUnknown(quantumUnknown);
            metrics.setClassicalStrengthHigh(classicalStrengthHigh);
            metrics.setClassicalStrengthMedium(classicalStrengthMedium);
            metrics.setClassicalStrengthLow(classicalStrengthLow);
            metrics.setExpiredCertificates(expiredCertificates);
            metrics.setExpiringCertificates(expiringCertificates);
            metrics.setPolicyViolations(policyViolations);
            metrics.setFirstOccurrence(now);
            metrics.setLastOccurrence(now);

            // Persist via native SQL since CryptoAssetMetrics is not a JDO entity
            persistCryptoMetrics(qm, metrics);

            LOGGER.debug("Crypto metrics updated for project %s: %d total assets".formatted(projectUuid, totalAssets));
        }
    }

    private void persistCryptoMetrics(final QueryManager qm, final CryptoAssetMetrics metrics) {
        final var query = qm.getPersistenceManager().newQuery(javax.jdo.Query.SQL, /* language=SQL */ """
                INSERT INTO "CRYPTOASSET_METRICS" (
                    "PROJECT_ID", "TOTAL_ASSETS", "ALGORITHM_COUNT", "PROTOCOL_COUNT",
                    "CERTIFICATE_COUNT", "RELATED_MATERIAL_COUNT",
                    "QUANTUM_SAFE", "QUANTUM_VULNERABLE", "QUANTUM_UNKNOWN",
                    "CLASSICAL_STRENGTH_HIGH", "CLASSICAL_STRENGTH_MEDIUM", "CLASSICAL_STRENGTH_LOW",
                    "EXPIRED_CERTIFICATES", "EXPIRING_CERTIFICATES", "POLICY_VIOLATIONS",
                    "FIRST_OCCURRENCE", "LAST_OCCURRENCE"
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """);
        try {
            query.executeWithArray(
                    metrics.getProjectId(),
                    metrics.getTotalAssets(), metrics.getAlgorithmCount(), metrics.getProtocolCount(),
                    metrics.getCertificateCount(), metrics.getRelatedMaterialCount(),
                    metrics.getQuantumSafe(), metrics.getQuantumVulnerable(), metrics.getQuantumUnknown(),
                    metrics.getClassicalStrengthHigh(), metrics.getClassicalStrengthMedium(), metrics.getClassicalStrengthLow(),
                    metrics.getExpiredCertificates(), metrics.getExpiringCertificates(), metrics.getPolicyViolations(),
                    metrics.getFirstOccurrence(), metrics.getLastOccurrence()
            );
        } finally {
            query.closeAll();
        }
    }
}
