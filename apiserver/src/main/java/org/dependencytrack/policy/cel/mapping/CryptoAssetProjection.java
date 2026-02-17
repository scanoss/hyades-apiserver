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
package org.dependencytrack.policy.cel.mapping;

import java.sql.Timestamp;

public class CryptoAssetProjection {

    public long id;
    public String uuid;
    public String name;
    public String assetType;
    public String oid;
    public String description;

    // Algorithm fields
    public String algPrimitive;
    public String algMode;
    public String algPadding;
    public String algParameterSetIdentifier;
    public String algCurve;
    public Integer algClassicalSecurityLevel;
    public Integer algNistQuantumSecurityLevel;

    // Certificate fields
    public String certSubjectName;
    public String certIssuerName;
    public Timestamp certNotValidBefore;
    public Timestamp certNotValidAfter;
    public String certSignatureAlgorithmRef;

    // Protocol fields
    public String protoType;
    public String protoVersion;
    public String protoCipherSuites;

    // Related material fields
    public String rmType;
    public Integer rmSize;
    public String rmFormat;
    public String rmAlgorithmRef;

}
