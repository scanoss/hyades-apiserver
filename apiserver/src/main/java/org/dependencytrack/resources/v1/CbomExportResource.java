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
import org.dependencytrack.model.CryptoAsset;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.resources.v1.problems.ProblemDetails;
import org.json.JSONArray;
import org.json.JSONObject;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * JAX-RS resources for exporting Cryptographic Bill of Materials (CBOM).
 *
 * @since 5.7.0
 */
@Path("/v1/bom/cbom")
@Tag(name = "bom")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class CbomExportResource extends AbstractApiResource {

    @GET
    @Path("/project/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Exports a Cryptographic Bill of Materials (CBOM) for a specific project",
            description = "<p>Requires permission <strong>VIEW_CRYPTO_ASSETS</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A CBOM in CycloneDX JSON format",
                    content = @Content(schema = @Schema(type = "string"))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_CRYPTO_ASSETS)
    public Response exportCbom(
            @Parameter(description = "The UUID of the project to export a CBOM for", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
            requireAccess(qm, project);
            final List<CryptoAsset> assets = qm.getAllCryptoAssetsList(project);

            final JSONObject bom = new JSONObject();
            bom.put("bomFormat", "CycloneDX");
            bom.put("specVersion", "1.6");
            bom.put("version", 1);
            bom.put("serialNumber", "urn:uuid:" + UUID.randomUUID());

            final JSONObject metadata = new JSONObject();
            metadata.put("timestamp", Instant.now().toString());
            final JSONObject tool = new JSONObject();
            tool.put("vendor", "OWASP");
            tool.put("name", "Dependency-Track");
            final JSONArray tools = new JSONArray();
            tools.put(tool);
            metadata.put("tools", tools);

            final JSONObject component = new JSONObject();
            component.put("type", "application");
            component.put("name", project.getName());
            if (project.getVersion() != null) {
                component.put("version", project.getVersion());
            }
            metadata.put("component", component);
            bom.put("metadata", metadata);

            final JSONArray components = new JSONArray();
            for (final CryptoAsset asset : assets) {
                final JSONObject comp = new JSONObject();
                comp.put("type", "cryptographic-asset");
                comp.put("name", asset.getName());
                if (asset.getBomRef() != null) {
                    comp.put("bom-ref", asset.getBomRef());
                }
                if (asset.getDescription() != null) {
                    comp.put("description", asset.getDescription());
                }

                final JSONObject cryptoProps = new JSONObject();
                cryptoProps.put("assetType", asset.getAssetType().name().toLowerCase().replace("_", "-"));
                if (asset.getOid() != null) {
                    cryptoProps.put("oid", asset.getOid());
                }

                if (asset.getOccurrences() != null) {
                    try {
                        cryptoProps.put("occurrences", new JSONArray(asset.getOccurrences()));
                    } catch (Exception ignored) {
                    }
                }

                switch (asset.getAssetType()) {
                    case ALGORITHM -> {
                        if (asset.getAlgorithm() != null) {
                            final JSONObject algProps = new JSONObject();
                            if (asset.getAlgorithm().getPrimitive() != null) {
                                algProps.put("primitive", asset.getAlgorithm().getPrimitive().name().toLowerCase().replace("_", "-"));
                            }
                            if (asset.getAlgorithm().getAlgorithmMode() != null) {
                                algProps.put("mode", asset.getAlgorithm().getAlgorithmMode());
                            }
                            if (asset.getAlgorithm().getPadding() != null) {
                                algProps.put("padding", asset.getAlgorithm().getPadding());
                            }
                            if (asset.getAlgorithm().getParameterSetIdentifier() != null) {
                                algProps.put("parameterSetIdentifier", asset.getAlgorithm().getParameterSetIdentifier());
                            }
                            if (asset.getAlgorithm().getCurve() != null) {
                                algProps.put("curve", asset.getAlgorithm().getCurve());
                            }
                            if (asset.getAlgorithm().getCryptoFunctions() != null) {
                                try {
                                    algProps.put("cryptoFunctions", new JSONArray(asset.getAlgorithm().getCryptoFunctions()));
                                } catch (Exception ignored) {
                                }
                            }
                            if (asset.getAlgorithm().getClassicalSecurityLevel() != null) {
                                algProps.put("classicalSecurityLevel", asset.getAlgorithm().getClassicalSecurityLevel());
                            }
                            if (asset.getAlgorithm().getNistQuantumSecurityLevel() != null) {
                                algProps.put("nistQuantumSecurityLevel", asset.getAlgorithm().getNistQuantumSecurityLevel());
                            }
                            cryptoProps.put("algorithmProperties", algProps);
                        }
                    }
                    case CERTIFICATE -> {
                        if (asset.getCertificate() != null) {
                            final JSONObject certProps = new JSONObject();
                            if (asset.getCertificate().getSubjectName() != null) {
                                certProps.put("subjectName", asset.getCertificate().getSubjectName());
                            }
                            if (asset.getCertificate().getIssuerName() != null) {
                                certProps.put("issuerName", asset.getCertificate().getIssuerName());
                            }
                            if (asset.getCertificate().getNotValidBefore() != null) {
                                certProps.put("notValidBefore", asset.getCertificate().getNotValidBefore().toInstant().toString());
                            }
                            if (asset.getCertificate().getNotValidAfter() != null) {
                                certProps.put("notValidAfter", asset.getCertificate().getNotValidAfter().toInstant().toString());
                            }
                            if (asset.getCertificate().getSignatureAlgorithmRef() != null) {
                                certProps.put("signatureAlgorithmRef", asset.getCertificate().getSignatureAlgorithmRef());
                            }
                            if (asset.getCertificate().getSubjectPublicKeyRef() != null) {
                                certProps.put("subjectPublicKeyRef", asset.getCertificate().getSubjectPublicKeyRef());
                            }
                            if (asset.getCertificate().getCertificateFormat() != null) {
                                certProps.put("certificateFormat", asset.getCertificate().getCertificateFormat());
                            }
                            if (asset.getCertificate().getCertificateExtension() != null) {
                                certProps.put("certificateExtension", asset.getCertificate().getCertificateExtension());
                            }
                            cryptoProps.put("certificateProperties", certProps);
                        }
                    }
                    case PROTOCOL -> {
                        if (asset.getProtocol() != null) {
                            final JSONObject protoProps = new JSONObject();
                            if (asset.getProtocol().getProtocolType() != null) {
                                protoProps.put("type", asset.getProtocol().getProtocolType());
                            }
                            if (asset.getProtocol().getProtocolVersion() != null) {
                                protoProps.put("version", asset.getProtocol().getProtocolVersion());
                            }
                            if (asset.getProtocol().getCipherSuites() != null) {
                                try {
                                    protoProps.put("cipherSuites", new JSONArray(asset.getProtocol().getCipherSuites()));
                                } catch (Exception ignored) {
                                }
                            }
                            cryptoProps.put("protocolProperties", protoProps);
                        }
                    }
                    case RELATED_CRYPTO_MATERIAL -> {
                        if (asset.getRelatedMaterial() != null) {
                            final JSONObject matProps = new JSONObject();
                            if (asset.getRelatedMaterial().getType() != null) {
                                matProps.put("type", asset.getRelatedMaterial().getType().name().toLowerCase().replace("_", "-"));
                            }
                            if (asset.getRelatedMaterial().getMaterialSize() != null) {
                                matProps.put("size", asset.getRelatedMaterial().getMaterialSize());
                            }
                            if (asset.getRelatedMaterial().getMaterialFormat() != null) {
                                matProps.put("format", asset.getRelatedMaterial().getMaterialFormat());
                            }
                            if (asset.getRelatedMaterial().getAlgorithmRef() != null) {
                                matProps.put("algorithmRef", asset.getRelatedMaterial().getAlgorithmRef());
                            }
                            cryptoProps.put("relatedCryptoMaterialProperties", matProps);
                        }
                    }
                }

                comp.put("cryptoProperties", cryptoProps);
                components.put(comp);
            }
            bom.put("components", components);

            return Response.ok(bom.toString(2))
                    .header("Content-Disposition", "attachment; filename=\"cbom-" + project.getUuid() + ".json\"")
                    .build();
        }
    }
}
