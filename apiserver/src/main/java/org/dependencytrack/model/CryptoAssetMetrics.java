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
import com.fasterxml.jackson.annotation.JsonInclude;
import jakarta.validation.constraints.NotNull;

import java.io.Serializable;
import java.util.Date;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class CryptoAssetMetrics implements Serializable {

    private static final long serialVersionUID = 7L;

    @JsonIgnore
    private long projectId;

    private int totalAssets;
    private int algorithmCount;
    private int protocolCount;
    private int certificateCount;
    private int relatedMaterialCount;
    private int quantumSafe;
    private int quantumVulnerable;
    private int quantumUnknown;
    private int classicalStrengthHigh;
    private int classicalStrengthMedium;
    private int classicalStrengthLow;
    private int expiredCertificates;
    private int expiringCertificates;
    private int policyViolations;

    @NotNull
    private Date firstOccurrence;

    @NotNull
    private Date lastOccurrence;

    public long getProjectId() {
        return projectId;
    }

    public void setProjectId(long projectId) {
        this.projectId = projectId;
    }

    public int getTotalAssets() {
        return totalAssets;
    }

    public void setTotalAssets(int totalAssets) {
        this.totalAssets = totalAssets;
    }

    public int getAlgorithmCount() {
        return algorithmCount;
    }

    public void setAlgorithmCount(int algorithmCount) {
        this.algorithmCount = algorithmCount;
    }

    public int getProtocolCount() {
        return protocolCount;
    }

    public void setProtocolCount(int protocolCount) {
        this.protocolCount = protocolCount;
    }

    public int getCertificateCount() {
        return certificateCount;
    }

    public void setCertificateCount(int certificateCount) {
        this.certificateCount = certificateCount;
    }

    public int getRelatedMaterialCount() {
        return relatedMaterialCount;
    }

    public void setRelatedMaterialCount(int relatedMaterialCount) {
        this.relatedMaterialCount = relatedMaterialCount;
    }

    public int getQuantumSafe() {
        return quantumSafe;
    }

    public void setQuantumSafe(int quantumSafe) {
        this.quantumSafe = quantumSafe;
    }

    public int getQuantumVulnerable() {
        return quantumVulnerable;
    }

    public void setQuantumVulnerable(int quantumVulnerable) {
        this.quantumVulnerable = quantumVulnerable;
    }

    public int getQuantumUnknown() {
        return quantumUnknown;
    }

    public void setQuantumUnknown(int quantumUnknown) {
        this.quantumUnknown = quantumUnknown;
    }

    public int getClassicalStrengthHigh() {
        return classicalStrengthHigh;
    }

    public void setClassicalStrengthHigh(int classicalStrengthHigh) {
        this.classicalStrengthHigh = classicalStrengthHigh;
    }

    public int getClassicalStrengthMedium() {
        return classicalStrengthMedium;
    }

    public void setClassicalStrengthMedium(int classicalStrengthMedium) {
        this.classicalStrengthMedium = classicalStrengthMedium;
    }

    public int getClassicalStrengthLow() {
        return classicalStrengthLow;
    }

    public void setClassicalStrengthLow(int classicalStrengthLow) {
        this.classicalStrengthLow = classicalStrengthLow;
    }

    public int getExpiredCertificates() {
        return expiredCertificates;
    }

    public void setExpiredCertificates(int expiredCertificates) {
        this.expiredCertificates = expiredCertificates;
    }

    public int getExpiringCertificates() {
        return expiringCertificates;
    }

    public void setExpiringCertificates(int expiringCertificates) {
        this.expiringCertificates = expiringCertificates;
    }

    public int getPolicyViolations() {
        return policyViolations;
    }

    public void setPolicyViolations(int policyViolations) {
        this.policyViolations = policyViolations;
    }

    public Date getFirstOccurrence() {
        return firstOccurrence;
    }

    public void setFirstOccurrence(Date firstOccurrence) {
        this.firstOccurrence = firstOccurrence;
    }

    public Date getLastOccurrence() {
        return lastOccurrence;
    }

    public void setLastOccurrence(Date lastOccurrence) {
        this.lastOccurrence = lastOccurrence;
    }
}
