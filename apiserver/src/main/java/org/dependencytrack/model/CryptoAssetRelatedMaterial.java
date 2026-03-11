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

@PersistenceCapable(table = "CRYPTOASSET_RELATED_MATERIAL")
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class CryptoAssetRelatedMaterial implements Serializable {

    private static final long serialVersionUID = 5L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent(defaultFetchGroup = "true")
    @ForeignKey(name = "CRYPTOASSET_RELATED_MATERIAL_FK", updateAction = ForeignKeyAction.NONE, deleteAction = ForeignKeyAction.CASCADE, deferred = "true")
    @Column(name = "CRYPTOASSET_ID", allowsNull = "false")
    @JsonIgnore
    private CryptoAsset cryptoAsset;

    @Persistent
    @Column(name = "MATERIAL_TYPE", jdbcType = "VARCHAR")
    private RelatedCryptoMaterialType type;

    @Persistent
    @Column(name = "MATERIAL_SIZE")
    private Integer materialSize;

    @Persistent
    @Column(name = "MATERIAL_FORMAT")
    @Size(max = 255)
    private String materialFormat;

    @Persistent
    @Column(name = "ALGORITHM_REF")
    @Size(max = 255)
    private String algorithmRef;

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

    public RelatedCryptoMaterialType getType() {
        return type;
    }

    public void setType(RelatedCryptoMaterialType type) {
        this.type = type;
    }

    public Integer getMaterialSize() {
        return materialSize;
    }

    public void setMaterialSize(Integer materialSize) {
        this.materialSize = materialSize;
    }

    public String getMaterialFormat() {
        return materialFormat;
    }

    public void setMaterialFormat(String materialFormat) {
        this.materialFormat = materialFormat;
    }

    public String getAlgorithmRef() {
        return algorithmRef;
    }

    public void setAlgorithmRef(String algorithmRef) {
        this.algorithmRef = algorithmRef;
    }
}
