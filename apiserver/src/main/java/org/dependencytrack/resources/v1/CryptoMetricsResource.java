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
package org.dependencytrack.resources.v1;

import alpine.server.auth.PermissionRequired;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.CryptoAssetMetrics;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.resources.v1.problems.ProblemDetails;

import java.util.Date;
import java.util.List;

/**
 * JAX-RS resources for processing crypto asset metrics.
 *
 * @since 5.7.0
 */
@Path("/v1/metrics/crypto")
@Tag(name = "metrics")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class CryptoMetricsResource extends AbstractApiResource {

    @GET
    @Path("/project/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns current crypto asset metrics for a specific project",
            description = "<p>Requires permission <strong>VIEW_CRYPTO_ASSETS</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Current crypto asset metrics for a specific project",
                    content = @Content(schema = @Schema(implementation = CryptoAssetMetrics.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_CRYPTO_ASSETS)
    public Response getCryptoMetrics(
            @Parameter(description = "The UUID of the project to retrieve crypto metrics for", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
            requireAccess(qm, project);
            // Query via native SQL since CryptoAssetMetrics is not a JDO entity
            final var query = qm.getPersistenceManager().newQuery(javax.jdo.Query.SQL,
                    "SELECT * FROM \"CRYPTOASSET_METRICS\" WHERE \"PROJECT_ID\" = ? ORDER BY \"LAST_OCCURRENCE\" DESC FETCH FIRST 1 ROW ONLY");
            query.setParameters(project.getId());
            try {
                @SuppressWarnings("unchecked")
                final List<?> results = (List<?>) query.executeList();
                if (results == null || results.isEmpty()) {
                    return Response.ok(new CryptoAssetMetrics()).build();
                }
                final Object[] row = (Object[]) results.get(0);
                final var metrics = new CryptoAssetMetrics();
                metrics.setProjectId(((Number) row[1]).longValue());
                metrics.setTotalAssets(row[2] != null ? ((Number) row[2]).intValue() : 0);
                metrics.setAlgorithmCount(row[3] != null ? ((Number) row[3]).intValue() : 0);
                metrics.setProtocolCount(row[4] != null ? ((Number) row[4]).intValue() : 0);
                metrics.setCertificateCount(row[5] != null ? ((Number) row[5]).intValue() : 0);
                metrics.setRelatedMaterialCount(row[6] != null ? ((Number) row[6]).intValue() : 0);
                metrics.setQuantumSafe(row[7] != null ? ((Number) row[7]).intValue() : 0);
                metrics.setQuantumVulnerable(row[8] != null ? ((Number) row[8]).intValue() : 0);
                metrics.setQuantumUnknown(row[9] != null ? ((Number) row[9]).intValue() : 0);
                metrics.setClassicalStrengthHigh(row[10] != null ? ((Number) row[10]).intValue() : 0);
                metrics.setClassicalStrengthMedium(row[11] != null ? ((Number) row[11]).intValue() : 0);
                metrics.setClassicalStrengthLow(row[12] != null ? ((Number) row[12]).intValue() : 0);
                metrics.setExpiredCertificates(row[13] != null ? ((Number) row[13]).intValue() : 0);
                metrics.setExpiringCertificates(row[14] != null ? ((Number) row[14]).intValue() : 0);
                metrics.setPolicyViolations(row[15] != null ? ((Number) row[15]).intValue() : 0);
                if (row[16] != null) metrics.setFirstOccurrence((Date) row[16]);
                if (row[17] != null) metrics.setLastOccurrence((Date) row[17]);
                return Response.ok(metrics).build();
            } finally {
                query.closeAll();
            }
        }
    }
}
