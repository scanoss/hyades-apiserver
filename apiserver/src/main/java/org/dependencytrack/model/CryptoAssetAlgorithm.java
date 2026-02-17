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

@PersistenceCapable(table = "CRYPTOASSET_ALGORITHM")
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class CryptoAssetAlgorithm implements Serializable {

    private static final long serialVersionUID = 2L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent(defaultFetchGroup = "true")
    @ForeignKey(name = "CRYPTOASSET_ALGORITHM_FK", updateAction = ForeignKeyAction.NONE, deleteAction = ForeignKeyAction.CASCADE, deferred = "true")
    @Column(name = "CRYPTOASSET_ID", allowsNull = "false")
    @JsonIgnore
    private CryptoAsset cryptoAsset;

    @Persistent
    @Column(name = "PRIMITIVE", jdbcType = "VARCHAR")
    private CryptoPrimitive primitive;

    @Persistent
    @Column(name = "ALGORITHM_MODE")
    @Size(max = 255)
    private String algorithmMode;

    @Persistent
    @Column(name = "PADDING")
    @Size(max = 255)
    private String padding;

    @Persistent
    @Column(name = "PARAMETER_SET_IDENTIFIER")
    @Size(max = 255)
    private String parameterSetIdentifier;

    @Persistent
    @Column(name = "CURVE")
    @Size(max = 255)
    private String curve;

    @Persistent
    @Column(name = "CRYPTO_FUNCTIONS", jdbcType = "CLOB")
    private String cryptoFunctions;

    @Persistent
    @Column(name = "CLASSICAL_SECURITY_LEVEL")
    private Integer classicalSecurityLevel;

    @Persistent
    @Column(name = "NIST_QUANTUM_SECURITY_LEVEL")
    private Integer nistQuantumSecurityLevel;

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

    public CryptoPrimitive getPrimitive() {
        return primitive;
    }

    public void setPrimitive(CryptoPrimitive primitive) {
        this.primitive = primitive;
    }

    public String getAlgorithmMode() {
        return algorithmMode;
    }

    public void setAlgorithmMode(String algorithmMode) {
        this.algorithmMode = algorithmMode;
    }

    public String getPadding() {
        return padding;
    }

    public void setPadding(String padding) {
        this.padding = padding;
    }

    public String getParameterSetIdentifier() {
        return parameterSetIdentifier;
    }

    public void setParameterSetIdentifier(String parameterSetIdentifier) {
        this.parameterSetIdentifier = parameterSetIdentifier;
    }

    public String getCurve() {
        return curve;
    }

    public void setCurve(String curve) {
        this.curve = curve;
    }

    public String getCryptoFunctions() {
        return cryptoFunctions;
    }

    public void setCryptoFunctions(String cryptoFunctions) {
        this.cryptoFunctions = cryptoFunctions;
    }

    public Integer getClassicalSecurityLevel() {
        return classicalSecurityLevel;
    }

    public void setClassicalSecurityLevel(Integer classicalSecurityLevel) {
        this.classicalSecurityLevel = classicalSecurityLevel;
    }

    public Integer getNistQuantumSecurityLevel() {
        return nistQuantumSecurityLevel;
    }

    public void setNistQuantumSecurityLevel(Integer nistQuantumSecurityLevel) {
        this.nistQuantumSecurityLevel = nistQuantumSecurityLevel;
    }
}
