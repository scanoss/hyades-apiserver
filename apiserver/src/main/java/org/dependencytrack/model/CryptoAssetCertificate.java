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
import jakarta.validation.constraints.Size;

import javax.jdo.annotations.Column;
import javax.jdo.annotations.ForeignKey;
import javax.jdo.annotations.ForeignKeyAction;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import java.io.Serializable;
import java.util.Date;

@PersistenceCapable(table = "CRYPTOASSET_CERTIFICATE")
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class CryptoAssetCertificate implements Serializable {

    private static final long serialVersionUID = 3L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent(defaultFetchGroup = "true")
    @ForeignKey(name = "CRYPTOASSET_CERTIFICATE_FK", updateAction = ForeignKeyAction.NONE, deleteAction = ForeignKeyAction.CASCADE, deferred = "true")
    @Column(name = "CRYPTOASSET_ID", allowsNull = "false")
    @JsonIgnore
    private CryptoAsset cryptoAsset;

    @Persistent
    @Column(name = "SUBJECT_NAME")
    @Size(max = 255)
    private String subjectName;

    @Persistent
    @Column(name = "ISSUER_NAME")
    @Size(max = 255)
    private String issuerName;

    @Persistent
    @Column(name = "NOT_VALID_BEFORE")
    private Date notValidBefore;

    @Persistent
    @Column(name = "NOT_VALID_AFTER")
    private Date notValidAfter;

    @Persistent
    @Column(name = "SIGNATURE_ALGORITHM_REF")
    @Size(max = 255)
    private String signatureAlgorithmRef;

    @Persistent
    @Column(name = "SUBJECT_PUBLIC_KEY_REF")
    @Size(max = 255)
    private String subjectPublicKeyRef;

    @Persistent
    @Column(name = "CERTIFICATE_FORMAT")
    @Size(max = 255)
    private String certificateFormat;

    @Persistent
    @Column(name = "CERTIFICATE_EXTENSION")
    @Size(max = 255)
    private String certificateExtension;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public CryptoAsset getCryptoAsset() {
        return cryptoAsset;
    }

    public void setCryptoAsset(CryptoAsset cryptoAsset) {
        this.cryptoAsset = cryptoAsset;
    }

    public String getSubjectName() {
        return subjectName;
    }

    public void setSubjectName(String subjectName) {
        this.subjectName = subjectName;
    }

    public String getIssuerName() {
        return issuerName;
    }

    public void setIssuerName(String issuerName) {
        this.issuerName = issuerName;
    }

    public Date getNotValidBefore() {
        return notValidBefore;
    }

    public void setNotValidBefore(Date notValidBefore) {
        this.notValidBefore = notValidBefore;
    }

    public Date getNotValidAfter() {
        return notValidAfter;
    }

    public void setNotValidAfter(Date notValidAfter) {
        this.notValidAfter = notValidAfter;
    }

    public String getSignatureAlgorithmRef() {
        return signatureAlgorithmRef;
    }

    public void setSignatureAlgorithmRef(String signatureAlgorithmRef) {
        this.signatureAlgorithmRef = signatureAlgorithmRef;
    }

    public String getSubjectPublicKeyRef() {
        return subjectPublicKeyRef;
    }

    public void setSubjectPublicKeyRef(String subjectPublicKeyRef) {
        this.subjectPublicKeyRef = subjectPublicKeyRef;
    }

    public String getCertificateFormat() {
        return certificateFormat;
    }

    public void setCertificateFormat(String certificateFormat) {
        this.certificateFormat = certificateFormat;
    }

    public String getCertificateExtension() {
        return certificateExtension;
    }

    public void setCertificateExtension(String certificateExtension) {
        this.certificateExtension = certificateExtension;
    }
}
