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

import alpine.persistence.PaginatedResult;
import alpine.server.auth.PermissionRequired;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.CryptoAsset;
import org.dependencytrack.model.CryptoAssetType;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.resources.v1.problems.ProblemDetails;

import java.util.UUID;

/**
 * JAX-RS resources for processing crypto assets.
 *
 * @since 5.7.0
 */
@Path("/v1/crypto-asset")
@Tag(name = "crypto-asset")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class CryptoAssetResource extends AbstractApiResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all crypto assets",
            description = "<p>Requires permission <strong>VIEW_CRYPTO_ASSETS</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of crypto assets",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = CryptoAsset.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VIEW_CRYPTO_ASSETS)
    public Response getAllCryptoAssets(
            @Parameter(description = "Optionally filter by crypto asset type")
            @QueryParam("type") String type) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            if (type != null) {
                try {
                    final CryptoAssetType assetType = CryptoAssetType.valueOf(type.toUpperCase());
                    final PaginatedResult result = qm.getAllCryptoAssetsByType(assetType);
                    return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
                } catch (IllegalArgumentException e) {
                    return Response.status(Response.Status.BAD_REQUEST).entity("Invalid crypto asset type.").build();
                }
            }
            final PaginatedResult result = qm.getAllCryptoAssets();
            return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        }
    }

    @GET
    @Path("/project/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns crypto assets for a specific project",
            description = "<p>Requires permission <strong>VIEW_CRYPTO_ASSETS</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of crypto assets",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = CryptoAsset.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_CRYPTO_ASSETS)
    public Response getCryptoAssetsByProject(
            @Parameter(description = "The UUID of the project", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            @Parameter(description = "Optionally filter by crypto asset type")
            @QueryParam("type") String type) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
            requireAccess(qm, project);
            final PaginatedResult result;
            if (type != null) {
                try {
                    result = qm.getCryptoAssetsByType(project, CryptoAssetType.valueOf(type.toUpperCase()));
                } catch (IllegalArgumentException e) {
                    return Response.status(Response.Status.BAD_REQUEST).entity("Invalid crypto asset type.").build();
                }
            } else {
                result = qm.getCryptoAssets(project);
            }
            return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        }
    }

    @GET
    @Path("/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a specific crypto asset",
            description = "<p>Requires permission <strong>VIEW_CRYPTO_ASSETS</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A crypto asset",
                    content = @Content(schema = @Schema(implementation = CryptoAsset.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The crypto asset could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_CRYPTO_ASSETS)
    public Response getCryptoAsset(
            @Parameter(description = "The UUID of the crypto asset", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final CryptoAsset asset = qm.getCryptoAssetByUuid(UUID.fromString(uuid));
            if (asset == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The crypto asset could not be found.").build();
            }
            requireAccess(qm, asset.getProject());
            return Response.ok(asset).build();
        }
    }

    @DELETE
    @Path("/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Deletes a crypto asset",
            description = "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Crypto asset removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The crypto asset could not be found")
    })
    @PermissionRequired(Permissions.Constants.PORTFOLIO_MANAGEMENT)
    public Response deleteCryptoAsset(
            @Parameter(description = "The UUID of the crypto asset", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final CryptoAsset asset = qm.getCryptoAssetByUuid(UUID.fromString(uuid));
            if (asset == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The crypto asset could not be found.").build();
            }
            requireAccess(qm, asset.getProject());
            qm.deleteCryptoAsset(asset);
            return Response.status(Response.Status.NO_CONTENT).build();
        }
    }
}
