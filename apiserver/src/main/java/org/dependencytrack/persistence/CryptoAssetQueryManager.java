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
package org.dependencytrack.persistence;

import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import org.dependencytrack.model.CryptoAsset;
import org.dependencytrack.model.CryptoAssetAlgorithm;
import org.dependencytrack.model.CryptoAssetAnalysis;
import org.dependencytrack.model.CryptoAssetAnalysisState;
import org.dependencytrack.model.CryptoAssetCertificate;
import org.dependencytrack.model.CryptoAssetMetrics;
import org.dependencytrack.model.CryptoAssetProtocol;
import org.dependencytrack.model.CryptoAssetRelatedMaterial;
import org.dependencytrack.model.CryptoAssetType;
import org.dependencytrack.model.Project;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

final class CryptoAssetQueryManager extends QueryManager implements IQueryManager {

    CryptoAssetQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    CryptoAssetQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    public PaginatedResult getCryptoAssets(final Project project) {
        final Query<CryptoAsset> query = pm.newQuery(CryptoAsset.class, "project == :project");
        if (orderBy == null) {
            query.setOrdering("name asc, id asc");
        }
        return execute(query, Map.of("project", project));
    }

    public PaginatedResult getCryptoAssetsByType(final Project project, final CryptoAssetType type) {
        final Query<CryptoAsset> query = pm.newQuery(CryptoAsset.class, "project == :project && assetType == :type");
        if (orderBy == null) {
            query.setOrdering("name asc, id asc");
        }
        return execute(query, Map.of("project", project, "type", type));
    }

    public PaginatedResult getAllCryptoAssets() {
        final Query<CryptoAsset> query = pm.newQuery(CryptoAsset.class);
        if (orderBy == null) {
            query.setOrdering("name asc, id asc");
        }
        return execute(query);
    }

    public PaginatedResult getAllCryptoAssetsByType(final CryptoAssetType type) {
        final Query<CryptoAsset> query = pm.newQuery(CryptoAsset.class, "assetType == :type");
        if (orderBy == null) {
            query.setOrdering("name asc, id asc");
        }
        return execute(query, Map.of("type", type));
    }

    public CryptoAsset getCryptoAssetByUuid(final UUID uuid) {
        final Query<CryptoAsset> query = pm.newQuery(CryptoAsset.class, "uuid == :uuid");
        try {
            return singleResult(query.execute(uuid));
        } finally {
            query.closeAll();
        }
    }

    public CryptoAsset getCryptoAssetByBomRef(final Project project, final String bomRef) {
        final Query<CryptoAsset> query = pm.newQuery(CryptoAsset.class, "project == :project && bomRef == :bomRef");
        try {
            return singleResult(query.execute(project, bomRef));
        } finally {
            query.closeAll();
        }
    }

    public CryptoAsset createCryptoAsset(final CryptoAsset cryptoAsset) {
        return pm.makePersistent(cryptoAsset);
    }

    public CryptoAssetAlgorithm createCryptoAssetAlgorithm(final CryptoAssetAlgorithm algorithm) {
        return pm.makePersistent(algorithm);
    }

    public CryptoAssetCertificate createCryptoAssetCertificate(final CryptoAssetCertificate certificate) {
        return pm.makePersistent(certificate);
    }

    public CryptoAssetProtocol createCryptoAssetProtocol(final CryptoAssetProtocol protocol) {
        return pm.makePersistent(protocol);
    }

    public CryptoAssetRelatedMaterial createCryptoAssetRelatedMaterial(final CryptoAssetRelatedMaterial material) {
        return pm.makePersistent(material);
    }

    public void deleteCryptoAsset(final CryptoAsset cryptoAsset) {
        // Sub-entities cascade via DB FK ON DELETE CASCADE
        pm.deletePersistent(cryptoAsset);
    }

    @SuppressWarnings("unchecked")
    public void deleteCryptoAssets(final Project project) {
        // Delete analyses first (they reference both project and cryptoAsset)
        final Query<CryptoAssetAnalysis> analysisQuery = pm.newQuery(CryptoAssetAnalysis.class, "project == :project");
        try {
            analysisQuery.deletePersistentAll(project);
        } finally {
            analysisQuery.closeAll();
        }

        // Delete crypto assets (sub-entities cascade via FK)
        final Query<CryptoAsset> query = pm.newQuery(CryptoAsset.class, "project == :project");
        try {
            query.deletePersistentAll(project);
        } finally {
            query.closeAll();
        }
    }

    public long getCryptoAssetCount(final Project project) {
        final Query<?> query = pm.newQuery(CryptoAsset.class, "project == :project");
        query.setResult("count(this)");
        try {
            return (Long) query.execute(project);
        } finally {
            query.closeAll();
        }
    }

    public CryptoAssetAnalysis getCryptoAssetAnalysis(final Project project, final CryptoAsset cryptoAsset) {
        final Query<CryptoAssetAnalysis> query = pm.newQuery(CryptoAssetAnalysis.class,
                "project == :project && cryptoAsset == :cryptoAsset");
        try {
            return singleResult(query.execute(project, cryptoAsset));
        } finally {
            query.closeAll();
        }
    }

    public PaginatedResult getCryptoAssetAnalyses(final Project project) {
        final Query<CryptoAssetAnalysis> query = pm.newQuery(CryptoAssetAnalysis.class, "project == :project");
        if (orderBy == null) {
            query.setOrdering("timestamp desc, id asc");
        }
        return execute(query, Map.of("project", project));
    }

    public CryptoAssetAnalysis createCryptoAssetAnalysis(final Project project, final CryptoAsset cryptoAsset,
                                                          final CryptoAssetAnalysisState state, final String justification,
                                                          final String response, final String details,
                                                          final String comment, final Boolean suppressed) {
        CryptoAssetAnalysis analysis = getCryptoAssetAnalysis(project, cryptoAsset);
        if (analysis == null) {
            analysis = new CryptoAssetAnalysis();
            analysis.setProject(project);
            analysis.setCryptoAsset(cryptoAsset);
        }
        analysis.setState(state != null ? state : CryptoAssetAnalysisState.NOT_SET);
        if (justification != null) analysis.setJustification(justification);
        if (response != null) analysis.setResponse(response);
        if (details != null) analysis.setDetails(details);
        if (comment != null) analysis.setComment(comment);
        if (suppressed != null) analysis.setSuppressed(suppressed);
        analysis.setTimestamp(new Date());
        return pm.makePersistent(analysis);
    }

    @SuppressWarnings("unchecked")
    public List<CryptoAsset> getAllCryptoAssetsList(final Project project) {
        final Query<CryptoAsset> query = pm.newQuery(CryptoAsset.class, "project == :project");
        query.setOrdering("name asc, id asc");
        try {
            return new ArrayList<>((List<CryptoAsset>) query.execute(project));
        } finally {
            query.closeAll();
        }
    }
}
