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
import java.util.Date;
import java.util.UUID;

@PersistenceCapable(table = "CRYPTOASSET_ANALYSIS")
@Unique(name = "CRYPTOASSET_COMPOSITE_IDX", members = {"project", "cryptoAsset"})
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class CryptoAssetAnalysis implements Serializable {

    private static final long serialVersionUID = 6L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent(defaultFetchGroup = "true")
    @ForeignKey(name = "CRYPTOASSET_ANALYSIS_PROJECT_FK", updateAction = ForeignKeyAction.NONE, deleteAction = ForeignKeyAction.CASCADE, deferred = "true")
    @Column(name = "PROJECT_ID", allowsNull = "false")
    @JsonIgnore
    private Project project;

    @Persistent(defaultFetchGroup = "true")
    @ForeignKey(name = "CRYPTOASSET_ANALYSIS_CRYPTOASSET_FK", updateAction = ForeignKeyAction.NONE, deleteAction = ForeignKeyAction.CASCADE, deferred = "true")
    @Column(name = "CRYPTOASSET_ID", allowsNull = "false")
    @JsonIgnore
    private CryptoAsset cryptoAsset;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "STATE", jdbcType = "VARCHAR", allowsNull = "false")
    @NotNull
    private CryptoAssetAnalysisState state;

    @Persistent
    @Column(name = "JUSTIFICATION", jdbcType = "CLOB")
    private String justification;

    @Persistent
    @Column(name = "RESPONSE")
    @Size(max = 255)
    private String response;

    @Persistent
    @Column(name = "DETAILS", jdbcType = "CLOB")
    private String details;

    @Persistent
    @Column(name = "COMMENT", jdbcType = "CLOB")
    private String comment;

    @Persistent
    @Column(name = "SUPPRESSED")
    @JsonProperty(value = "isSuppressed")
    private boolean suppressed;

    @Persistent
    @Column(name = "TIMESTAMP", allowsNull = "false")
    @NotNull
    private Date timestamp;

    @Persistent(customValueStrategy = "uuid")
    @Unique(name = "CRYPTOASSET_ANALYSIS_UUID_IDX")
    @Column(name = "UUID", sqlType = "UUID", allowsNull = "false")
    @NotNull
    private UUID uuid;

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

    public CryptoAsset getCryptoAsset() {
        return cryptoAsset;
    }

    public void setCryptoAsset(CryptoAsset cryptoAsset) {
        this.cryptoAsset = cryptoAsset;
    }

    public CryptoAssetAnalysisState getState() {
        return state;
    }

    public void setState(CryptoAssetAnalysisState state) {
        this.state = state;
    }

    public String getJustification() {
        return justification;
    }

    public void setJustification(String justification) {
        this.justification = justification;
    }

    public String getResponse() {
        return response;
    }

    public void setResponse(String response) {
        this.response = response;
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public boolean isSuppressed() {
        return suppressed;
    }

    public void setSuppressed(boolean suppressed) {
        this.suppressed = suppressed;
    }

    public Date getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Date timestamp) {
        this.timestamp = timestamp;
    }

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }
}
