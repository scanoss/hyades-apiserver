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
package org.dependencytrack.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import javax.jdo.annotations.Column;
import javax.jdo.annotations.ForeignKey;
import javax.jdo.annotations.ForeignKeyAction;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Unique;
import java.io.Serializable;
import java.util.UUID;

@PersistenceCapable(table = "CRYPTOASSET")
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class CryptoAsset implements Serializable {

    private static final long serialVersionUID = 1L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent(defaultFetchGroup = "true")
    @ForeignKey(name = "CRYPTOASSET_PROJECT_FK", updateAction = ForeignKeyAction.NONE, deleteAction = ForeignKeyAction.CASCADE, deferred = "true")
    @Column(name = "PROJECT_ID", allowsNull = "false")
    @JsonIgnore
    private Project project;

    @Persistent
    @Column(name = "NAME", allowsNull = "false")
    @NotNull
    @Size(max = 255)
    private String name;

    @Persistent
    @Column(name = "BOM_REF")
    @Size(max = 255)
    private String bomRef;

    @Persistent
    @Column(name = "ASSET_TYPE", allowsNull = "false", jdbcType = "VARCHAR")
    @NotNull
    private CryptoAssetType assetType;

    @Persistent
    @Column(name = "OID")
    @Size(max = 255)
    private String oid;

    @Persistent
    @Column(name = "DESCRIPTION", jdbcType = "CLOB")
    private String description;

    @Persistent
    @Column(name = "OCCURRENCES", jdbcType = "CLOB")
    private String occurrences;

    @Persistent(customValueStrategy = "uuid")
    @Unique(name = "CRYPTOASSET_UUID_IDX")
    @Column(name = "UUID", sqlType = "UUID", allowsNull = "false")
    @NotNull
    private UUID uuid;

    @Persistent(mappedBy = "cryptoAsset", defaultFetchGroup = "true")
    private CryptoAssetAlgorithm algorithm;

    @Persistent(mappedBy = "cryptoAsset", defaultFetchGroup = "true")
    private CryptoAssetCertificate certificate;

    @Persistent(mappedBy = "cryptoAsset", defaultFetchGroup = "true")
    private CryptoAssetProtocol protocol;

    @Persistent(mappedBy = "cryptoAsset", defaultFetchGroup = "true")
    private CryptoAssetRelatedMaterial relatedMaterial;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public Project getProject() {
        return project;
    }

    public void setProject(Project project) {
        this.project = project;
    }

    @JsonProperty("projectUuid")
    public UUID getProjectUuid() {
        return project != null ? project.getUuid() : null;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getBomRef() {
        return bomRef;
    }

    public void setBomRef(String bomRef) {
        this.bomRef = bomRef;
    }

    public CryptoAssetType getAssetType() {
        return assetType;
    }

    public void setAssetType(CryptoAssetType assetType) {
        this.assetType = assetType;
    }

    public String getOid() {
        return oid;
    }

    public void setOid(String oid) {
        this.oid = oid;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getOccurrences() {
        return occurrences;
    }

    public void setOccurrences(String occurrences) {
        this.occurrences = occurrences;
    }

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }

    public CryptoAssetAlgorithm getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(CryptoAssetAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    public CryptoAssetCertificate getCertificate() {
        return certificate;
    }

    public void setCertificate(CryptoAssetCertificate certificate) {
        this.certificate = certificate;
    }

    public CryptoAssetProtocol getProtocol() {
        return protocol;
    }

    public void setProtocol(CryptoAssetProtocol protocol) {
        this.protocol = protocol;
    }

    public CryptoAssetRelatedMaterial getRelatedMaterial() {
        return relatedMaterial;
    }

    public void setRelatedMaterial(CryptoAssetRelatedMaterial relatedMaterial) {
        this.relatedMaterial = relatedMaterial;
    }
}
