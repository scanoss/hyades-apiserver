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
package org.dependencytrack.resources.v1.vo;

import alpine.common.validation.RegexSequence;
import alpine.server.json.TrimmedStringDeserializer;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import org.dependencytrack.model.CryptoAssetAnalysisState;

/**
 * Defines a custom request object used when updating crypto asset analysis decisions.
 *
 * @since 5.7.0
 */
public class CryptoAnalysisRequest {

    @NotNull
    @Pattern(regexp = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", message = "The project must be a valid 36 character UUID")
    private final String project;

    @NotNull
    @Pattern(regexp = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", message = "The crypto asset must be a valid 36 character UUID")
    private final String cryptoAsset;

    private final CryptoAssetAnalysisState state;

    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS_PLUS, message = "The justification may only contain printable characters")
    private final String justification;

    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS_PLUS, message = "The response may only contain printable characters")
    private final String response;

    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS_PLUS, message = "The details may only contain printable characters")
    private final String details;

    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS_PLUS, message = "The comment may only contain printable characters")
    private final String comment;

    private final Boolean suppressed; // Optional. If not specified, we do not want to set value to false, thus using Boolean object rather than primitive.

    @JsonCreator
    public CryptoAnalysisRequest(@JsonProperty(value = "project", required = true) String project,
                                 @JsonProperty(value = "cryptoAsset", required = true) String cryptoAsset,
                                 @JsonProperty(value = "state") CryptoAssetAnalysisState state,
                                 @JsonProperty(value = "justification") String justification,
                                 @JsonProperty(value = "response") String response,
                                 @JsonProperty(value = "details") String details,
                                 @JsonProperty(value = "comment") String comment,
                                 @JsonProperty(value = "isSuppressed") Boolean suppressed) {
        this.project = project;
        this.cryptoAsset = cryptoAsset;
        this.state = state;
        this.justification = justification;
        this.response = response;
        this.details = details;
        this.comment = comment;
        this.suppressed = suppressed;
    }

    public String getProject() {
        return project;
    }

    public String getCryptoAsset() {
        return cryptoAsset;
    }

    public CryptoAssetAnalysisState getState() {
        if (state == null) {
            return CryptoAssetAnalysisState.NOT_SET;
        } else {
            return state;
        }
    }

    public String getJustification() {
        return justification;
    }

    public String getResponse() {
        return response;
    }

    public String getDetails() {
        return details;
    }

    public String getComment() {
        return comment;
    }

    public Boolean getSuppressed() {
        return suppressed;
    }
}
