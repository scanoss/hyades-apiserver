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
package org.dependencytrack.policy.cel;

import alpine.common.logging.Logger;
import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.google.api.expr.v1alpha1.Type;
import com.google.protobuf.Timestamp;
import com.google.protobuf.util.Timestamps;
import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.collections4.multimap.ArrayListValuedHashMap;
import org.apache.commons.collections4.multimap.HashSetValuedHashMap;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyCondition.Subject;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.persistence.CollectionIntegerConverter;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.policy.cel.CelPolicyScriptHost.CacheMode;
import org.dependencytrack.policy.cel.compat.CelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.ComponentAgeCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.ComponentHashCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.CoordinatesCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.CpeCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.CryptoAlgorithmCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.CryptoCertificateCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.CryptoMaterialCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.CryptoProtocolCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.CryptoQuantumCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.CweCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.EpssCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.LicenseCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.LicenseGroupCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.PackageUrlCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.SeverityCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.SwidTagIdCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.VersionCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.VersionDistanceCelScriptBuilder;
import org.dependencytrack.policy.cel.compat.VulnerabilityIdCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.mapping.ComponentProjection;
import org.dependencytrack.policy.cel.mapping.CryptoAssetProjection;
import org.dependencytrack.policy.cel.mapping.LicenseProjection;
import org.dependencytrack.policy.cel.mapping.VulnerabilityProjection;
import org.dependencytrack.policy.cel.persistence.CelPolicyDao;
import org.dependencytrack.proto.policy.v1.CryptoAlgorithm;
import org.dependencytrack.proto.policy.v1.CryptoAsset;
import org.dependencytrack.proto.policy.v1.CryptoCertificate;
import org.dependencytrack.proto.policy.v1.CryptoProtocol;
import org.dependencytrack.proto.policy.v1.CryptoRelatedMaterial;
import org.dependencytrack.proto.policy.v1.Vulnerability;
import org.dependencytrack.util.NotificationUtil;
import org.dependencytrack.util.VulnerabilityUtil;
import org.projectnessie.cel.tools.ScriptCreateException;
import org.projectnessie.cel.tools.ScriptException;
import org.slf4j.MDC;

import java.math.BigDecimal;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.util.Collections.emptyList;
import static org.apache.commons.collections4.MultiMapUtils.emptyMultiValuedMap;
import static org.apache.commons.lang3.StringUtils.trimToEmpty;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_UUID;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.policy.cel.definition.CelPolicyTypes.TYPE_COMPONENT;
import static org.dependencytrack.policy.cel.definition.CelPolicyTypes.TYPE_LICENSE;
import static org.dependencytrack.policy.cel.definition.CelPolicyTypes.TYPE_LICENSE_GROUP;
import static org.dependencytrack.policy.cel.definition.CelPolicyTypes.TYPE_PROJECT;
import static org.dependencytrack.policy.cel.definition.CelPolicyTypes.TYPE_VULNERABILITY;

/**
 * A policy engine powered by the Common Expression Language (CEL).
 *
 * @since 5.1.0
 */
public class CelPolicyEngine {

    private static final Logger LOGGER = Logger.getLogger(CelPolicyEngine.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Map<Subject, CelPolicyScriptSourceBuilder> SCRIPT_BUILDERS;
    private static final Set<Subject> CRYPTO_SUBJECTS = Set.of(
            Subject.CRYPTO_ALGORITHM_NAME,
            Subject.CRYPTO_ALGORITHM_PRIMITIVE,
            Subject.CRYPTO_ALGORITHM_PARAMETER_SET,
            Subject.CRYPTO_QUANTUM_SECURITY,
            Subject.CRYPTO_CLASSICAL_STRENGTH,
            Subject.CRYPTO_PROTOCOL_VERSION,
            Subject.CRYPTO_CERTIFICATE_EXPIRY,
            Subject.CRYPTO_CERTIFICATE_ALGORITHM,
            Subject.CRYPTO_MATERIAL_TYPE
    );

    static {
        SCRIPT_BUILDERS = new HashMap<>();
        SCRIPT_BUILDERS.put(Subject.CPE, new CpeCelPolicyScriptSourceBuilder());
        SCRIPT_BUILDERS.put(Subject.COMPONENT_HASH, new ComponentHashCelPolicyScriptSourceBuilder());
        SCRIPT_BUILDERS.put(Subject.COORDINATES, new CoordinatesCelPolicyScriptSourceBuilder());
        SCRIPT_BUILDERS.put(Subject.CWE, new CweCelPolicyScriptSourceBuilder());
        SCRIPT_BUILDERS.put(Subject.EXPRESSION, PolicyCondition::getValue);
        SCRIPT_BUILDERS.put(Subject.LICENSE, new LicenseCelPolicyScriptSourceBuilder());
        SCRIPT_BUILDERS.put(Subject.LICENSE_GROUP, new LicenseGroupCelPolicyScriptSourceBuilder());
        SCRIPT_BUILDERS.put(Subject.PACKAGE_URL, new PackageUrlCelPolicyScriptSourceBuilder());
        SCRIPT_BUILDERS.put(Subject.SEVERITY, new SeverityCelPolicyScriptSourceBuilder());
        SCRIPT_BUILDERS.put(Subject.SWID_TAGID, new SwidTagIdCelPolicyScriptSourceBuilder());
        SCRIPT_BUILDERS.put(Subject.VULNERABILITY_ID, new VulnerabilityIdCelPolicyScriptSourceBuilder());
        SCRIPT_BUILDERS.put(Subject.VERSION, new VersionCelPolicyScriptSourceBuilder());
        SCRIPT_BUILDERS.put(Subject.AGE, new ComponentAgeCelPolicyScriptSourceBuilder());
        SCRIPT_BUILDERS.put(Subject.VERSION_DISTANCE, new VersionDistanceCelScriptBuilder());
        SCRIPT_BUILDERS.put(Subject.EPSS, new EpssCelPolicyScriptSourceBuilder());
        // Crypto policy builders
        final var cryptoAlgorithmBuilder = new CryptoAlgorithmCelPolicyScriptSourceBuilder();
        SCRIPT_BUILDERS.put(Subject.CRYPTO_ALGORITHM_NAME, cryptoAlgorithmBuilder);
        SCRIPT_BUILDERS.put(Subject.CRYPTO_ALGORITHM_PRIMITIVE, cryptoAlgorithmBuilder);
        SCRIPT_BUILDERS.put(Subject.CRYPTO_ALGORITHM_PARAMETER_SET, cryptoAlgorithmBuilder);
        final var cryptoQuantumBuilder = new CryptoQuantumCelPolicyScriptSourceBuilder();
        SCRIPT_BUILDERS.put(Subject.CRYPTO_QUANTUM_SECURITY, cryptoQuantumBuilder);
        SCRIPT_BUILDERS.put(Subject.CRYPTO_CLASSICAL_STRENGTH, cryptoQuantumBuilder);
        SCRIPT_BUILDERS.put(Subject.CRYPTO_PROTOCOL_VERSION, new CryptoProtocolCelPolicyScriptSourceBuilder());
        final var cryptoCertBuilder = new CryptoCertificateCelPolicyScriptSourceBuilder();
        SCRIPT_BUILDERS.put(Subject.CRYPTO_CERTIFICATE_EXPIRY, cryptoCertBuilder);
        SCRIPT_BUILDERS.put(Subject.CRYPTO_CERTIFICATE_ALGORITHM, cryptoCertBuilder);
        SCRIPT_BUILDERS.put(Subject.CRYPTO_MATERIAL_TYPE, new CryptoMaterialCelPolicyScriptSourceBuilder());
    }

    private final CelPolicyScriptHost componentScriptHost;
    private final CelPolicyScriptHost cryptoScriptHost;

    public CelPolicyEngine() {
        this(CelPolicyScriptHost.getInstance(CelPolicyType.COMPONENT),
             CelPolicyScriptHost.getInstance(CelPolicyType.CRYPTO_ASSET));
    }

    CelPolicyEngine(final CelPolicyScriptHost componentScriptHost, final CelPolicyScriptHost cryptoScriptHost) {
        this.componentScriptHost = componentScriptHost;
        this.cryptoScriptHost = cryptoScriptHost;
    }

    /**
     * Evaluate {@link Policy}s for a {@link Project}.
     *
     * @param uuid The {@link UUID} of the {@link Project}
     */
    public void evaluateProject(final UUID uuid) {
        final long startTimeNs = System.nanoTime();

        try (final var qm = new QueryManager();
             final var celQm = new CelPolicyQueryManager(qm);
             var ignoredMdcProjectUuid = MDC.putCloseable(MDC_PROJECT_UUID, uuid.toString())) {
            // TODO: Should this entire procedure run in a single DB transaction?
            //   Would be better for atomicity, but could block DB connections for prolonged
            //   period of time for larger projects with many violations.

            final Project project = qm.getObjectByUuid(Project.class, uuid, List.of(Project.FetchGroup.IDENTIFIERS.name()));
            if (project == null) {
                LOGGER.warn("Project does not exist; Skipping");
                return;
            }

            LOGGER.info("Compiling policy scripts");
            final List<Pair<PolicyCondition, String>> allConditionScriptSrcPairs = getApplicableConditionScriptSrcPairs(celQm, project);
            if (allConditionScriptSrcPairs.isEmpty()) {
                LOGGER.info("No applicable policies found");
                celQm.reconcileViolations(project.getId(), emptyMultiValuedMap());
                celQm.reconcileCryptoViolations(project.getId(), emptyMultiValuedMap());
                return;
            }

            // Split conditions into component conditions and crypto conditions.
            final var componentConditionSrcPairs = new ArrayList<Pair<PolicyCondition, String>>();
            final var cryptoConditionSrcPairs = new ArrayList<Pair<PolicyCondition, String>>();
            for (final Pair<PolicyCondition, String> pair : allConditionScriptSrcPairs) {
                if (CRYPTO_SUBJECTS.contains(pair.getLeft().getSubject())) {
                    cryptoConditionSrcPairs.add(pair);
                } else {
                    componentConditionSrcPairs.add(pair);
                }
            }
            LOGGER.info("Found %d component conditions and %d crypto conditions"
                    .formatted(componentConditionSrcPairs.size(), cryptoConditionSrcPairs.size()));

            // Compile component conditions with the component script host.
            final List<Pair<PolicyCondition, CelPolicyScript>> componentConditionScriptPairs = componentConditionSrcPairs.stream()
                    .map(pair -> compileConditionScript(pair, componentScriptHost))
                    .filter(Objects::nonNull)
                    .toList();

            // Compile crypto conditions with the crypto script host.
            final List<Pair<PolicyCondition, CelPolicyScript>> cryptoConditionScriptPairs = cryptoConditionSrcPairs.stream()
                    .map(pair -> compileConditionScript(pair, cryptoScriptHost))
                    .filter(Objects::nonNull)
                    .toList();

            final Timestamp protoNow = Timestamps.now(); // Use consistent now timestamp for all evaluations.

            // --- Component evaluation (existing logic) ---
            if (!componentConditionScriptPairs.isEmpty()) {
                final MultiValuedMap<Type, String> requirements = determineScriptRequirements(componentConditionScriptPairs);
                LOGGER.debug("Requirements for %d component policy conditions: %s".formatted(componentConditionScriptPairs.size(), requirements));

                final org.dependencytrack.proto.policy.v1.Project protoProject;
                if (requirements.containsKey(TYPE_PROJECT)) {
                    final var inputProject = org.dependencytrack.proto.policy.v1.Project.newBuilder().setUuid(project.getUuid().toString()).build();
                    protoProject = withJdbiHandle(handle -> handle.attach(CelPolicyDao.class).loadRequiredFields(inputProject, requirements));
                } else {
                    protoProject = org.dependencytrack.proto.policy.v1.Project.getDefaultInstance();
                }
                final List<ComponentProjection> components = celQm.fetchAllComponents(project.getId(), requirements.get(TYPE_COMPONENT));

                final Map<Long, org.dependencytrack.proto.policy.v1.License> licenseById;
                if (requirements.containsKey(TYPE_LICENSE) || (requirements.containsKey(TYPE_COMPONENT) && requirements.get(TYPE_COMPONENT).contains("resolved_license"))) {
                    licenseById = celQm.fetchAllLicenses(project.getId(), requirements.get(TYPE_LICENSE), requirements.get(TYPE_LICENSE_GROUP)).stream()
                            .collect(Collectors.toMap(
                                    projection -> projection.id,
                                    CelPolicyEngine::mapToProto
                            ));
                } else {
                    licenseById = Collections.emptyMap();
                }

                final Map<Long, org.dependencytrack.proto.policy.v1.Vulnerability> protoVulnById;
                final Map<Long, List<Long>> vulnIdsByComponentId;
                if (requirements.containsKey(TYPE_VULNERABILITY)) {
                    protoVulnById = celQm.fetchAllVulnerabilities(project.getId(), requirements.get(TYPE_VULNERABILITY)).stream()
                            .collect(Collectors.toMap(
                                    projection -> projection.id,
                                    CelPolicyEngine::mapToProto
                            ));
                    vulnIdsByComponentId = celQm.fetchAllComponentsVulnerabilities(project.getId()).stream()
                            .collect(Collectors.groupingBy(
                                    projection -> projection.componentId,
                                    Collectors.mapping(projection -> projection.vulnerabilityId, Collectors.toList())
                            ));
                } else {
                    protoVulnById = Collections.emptyMap();
                    vulnIdsByComponentId = Collections.emptyMap();
                }

                final var conditionsViolated = new HashSetValuedHashMap<Long, PolicyCondition>();
                for (final ComponentProjection component : components) {
                    final org.dependencytrack.proto.policy.v1.Component protoComponent = mapToProto(component, licenseById);
                    final List<org.dependencytrack.proto.policy.v1.Vulnerability> protoVulns =
                            vulnIdsByComponentId.getOrDefault(component.id, emptyList()).stream()
                                    .map(protoVulnById::get)
                                    .toList();

                    conditionsViolated.putAll(component.id, evaluateConditions(componentConditionScriptPairs, Map.of(
                            CelPolicyVariable.COMPONENT.variableName(), protoComponent,
                            CelPolicyVariable.PROJECT.variableName(), protoProject,
                            CelPolicyVariable.VULNS.variableName(), protoVulns,
                            CelPolicyVariable.NOW.variableName(), protoNow
                    )));
                }

                final var violationsByComponentId = new ArrayListValuedHashMap<Long, PolicyViolation>();
                for (final long componentId : conditionsViolated.keySet()) {
                    violationsByComponentId.putAll(componentId, evaluatePolicyOperators(conditionsViolated.get(componentId)));
                }

                final List<Long> newComponentViolationIds = celQm.reconcileViolations(project.getId(), violationsByComponentId);
                LOGGER.info("Identified %d new component violations".formatted(newComponentViolationIds.size()));
                for (final Long newViolationId : newComponentViolationIds) {
                    NotificationUtil.analyzeNotificationCriteria(qm, newViolationId);
                }
            } else {
                celQm.reconcileViolations(project.getId(), emptyMultiValuedMap());
            }

            // --- Crypto asset evaluation ---
            if (!cryptoConditionScriptPairs.isEmpty()) {
                final List<CryptoAssetProjection> cryptoAssets = celQm.fetchAllCryptoAssets(project.getId());
                LOGGER.debug("Evaluating %d crypto conditions against %d crypto assets"
                        .formatted(cryptoConditionScriptPairs.size(), cryptoAssets.size()));

                final org.dependencytrack.proto.policy.v1.Project protoProjectForCrypto =
                        org.dependencytrack.proto.policy.v1.Project.getDefaultInstance();

                final var cryptoConditionsViolated = new HashSetValuedHashMap<Long, PolicyCondition>();
                for (final CryptoAssetProjection cryptoAsset : cryptoAssets) {
                    final CryptoAsset protoCryptoAsset = mapToProto(cryptoAsset);

                    cryptoConditionsViolated.putAll(cryptoAsset.id, evaluateConditions(cryptoConditionScriptPairs, Map.of(
                            CelPolicyVariable.CRYPTO_ASSET.variableName(), protoCryptoAsset,
                            CelPolicyVariable.PROJECT.variableName(), protoProjectForCrypto,
                            CelPolicyVariable.NOW.variableName(), protoNow
                    )));
                }

                final var cryptoViolationsByCryptoAssetId = new ArrayListValuedHashMap<Long, PolicyViolation>();
                for (final long cryptoAssetId : cryptoConditionsViolated.keySet()) {
                    cryptoViolationsByCryptoAssetId.putAll(cryptoAssetId,
                            evaluateCryptoPolicyOperators(cryptoConditionsViolated.get(cryptoAssetId)));
                }

                final List<Long> newCryptoViolationIds = celQm.reconcileCryptoViolations(project.getId(), cryptoViolationsByCryptoAssetId);
                LOGGER.info("Identified %d new crypto violations".formatted(newCryptoViolationIds.size()));
                for (final Long newViolationId : newCryptoViolationIds) {
                    NotificationUtil.analyzeNotificationCriteria(qm, newViolationId);
                }
            } else {
                celQm.reconcileCryptoViolations(project.getId(), emptyMultiValuedMap());
            }
        } finally {
            LOGGER.info("Evaluation completed in %s"
                    .formatted(Duration.ofNanos(System.nanoTime() - startTimeNs)));
        }
    }

    public void evaluateComponent(final UUID uuid) {
        // Evaluation of individual components is only triggered when they are added or modified
        // manually. As this happens very rarely, in low frequencies (due to being manual actions),
        // and because CEL policy evaluation is so efficient, it's not worth it to maintain extra
        // logic to handle component evaluation. Instead, re-purpose to project evaluation.

        final UUID projectUuid;
        try (final var qm = new QueryManager();
             final var celQm = new CelPolicyQueryManager(qm)) {
            projectUuid = celQm.getProjectUuidForComponentUuid(uuid);
        }

        if (projectUuid == null) {
            LOGGER.warn("Component with UUID %s does not exist; Skipping".formatted(uuid));
            return;
        }

        evaluateProject(projectUuid);
    }


    /**
     * Build CEL script sources for all conditions of all applicable policies.
     *
     * @param celQm   The {@link CelPolicyQueryManager} instance to use
     * @param project The {@link Project} to get applicable conditions for
     * @return {@link Pair}s of {@link PolicyCondition}s and their CEL script sources
     */
    private List<Pair<PolicyCondition, String>> getApplicableConditionScriptSrcPairs(final CelPolicyQueryManager celQm, final Project project) {
        final List<Policy> policies = celQm.getApplicablePolicies(project);
        if (policies.isEmpty()) {
            return emptyList();
        }

        return policies.stream()
                .map(Policy::getPolicyConditions)
                .flatMap(Collection::stream)
                .map(this::buildConditionScriptSrc)
                .filter(Objects::nonNull)
                .toList();
    }

    /**
     * Check what kind of data we need to evaluate all policy conditions.
     * <p>
     * Some conditions will be very simple and won't require us to load additional data (e.g. "component PURL matches 'XYZ'"),
     * whereas other conditions can span across multiple models, forcing us to load more data
     * (e.g. "project has tag 'public-facing' and component has a vulnerability with severity 'critical'").
     * <p>
     * What we want to avoid is loading data we don't need, and loading it multiple times.
     * Instead, only load what's really needed, and only do so once.
     *
     * @param conditionScriptPairs {@link Pair}s of {@link PolicyCondition}s and corresponding {@link CelPolicyScript}s
     * @return A {@link MultiValuedMap} containing all fields accessed on any {@link Type}, across all {@link CelPolicyScript}s
     */
    private static MultiValuedMap<Type, String> determineScriptRequirements(final Collection<Pair<PolicyCondition, CelPolicyScript>> conditionScriptPairs) {
        return conditionScriptPairs.stream()
                .map(Pair::getRight)
                .map(CelPolicyScript::getRequirements)
                .reduce(new HashSetValuedHashMap<>(), (lhs, rhs) -> {
                    lhs.putAll(rhs);
                    return lhs;
                });
    }

    private Pair<PolicyCondition, String> buildConditionScriptSrc(final PolicyCondition policyCondition) {
        final CelPolicyScriptSourceBuilder scriptBuilder = SCRIPT_BUILDERS.get(policyCondition.getSubject());
        if (scriptBuilder == null) {
            LOGGER.warn("""
                    No script builder found that is capable of handling subjects of type %s;\
                    Condition will be skipped""".formatted(policyCondition.getSubject()));
            return null;
        }

        final String scriptSrc = scriptBuilder.apply(policyCondition);
        if (scriptSrc == null) {
            LOGGER.warn("Unable to create CEL script for condition %s; Condition will be skipped".formatted(policyCondition.getUuid()));
            return null;
        }

        return Pair.of(policyCondition, scriptSrc);
    }

    private static Pair<PolicyCondition, CelPolicyScript> compileConditionScript(final Pair<PolicyCondition, String> conditionScriptSrcPair,
                                                                                   final CelPolicyScriptHost scriptHost) {
        final CelPolicyScript script;
        try {
            script = scriptHost.compile(conditionScriptSrcPair.getRight(), CacheMode.CACHE);
        } catch (ScriptCreateException e) {
            LOGGER.warn("Failed to compile script for condition %s; Condition will be skipped"
                    .formatted(conditionScriptSrcPair.getLeft().getUuid()), e);
            return null;
        }

        return Pair.of(conditionScriptSrcPair.getLeft(), script);
    }

    private static List<PolicyCondition> evaluateConditions(final Collection<Pair<PolicyCondition, CelPolicyScript>> conditionScriptPairs,
                                                            final Map<String, Object> scriptArguments) {
        final var conditionsViolated = new ArrayList<PolicyCondition>();

        for (final Pair<PolicyCondition, CelPolicyScript> conditionScriptPair : conditionScriptPairs) {
            final PolicyCondition condition = conditionScriptPair.getLeft();
            final CelPolicyScript script = conditionScriptPair.getRight();

            try {
                if (script.execute(scriptArguments)) {
                    conditionsViolated.add(condition);
                }
            } catch (ScriptException e) {
                LOGGER.warn("Failed to execute script for condition %s with arguments %s"
                        .formatted(condition.getUuid(), scriptArguments), e);
            }
        }

        return conditionsViolated;
    }

    private static List<PolicyViolation> evaluatePolicyOperators(final Collection<PolicyCondition> conditionsViolated) {
        final Map<Policy, List<PolicyCondition>> violatedConditionsByPolicy = conditionsViolated.stream()
                .collect(Collectors.groupingBy(PolicyCondition::getPolicy));

        return violatedConditionsByPolicy.entrySet().stream()
                .flatMap(policyAndViolatedConditions -> {
                    final Policy policy = policyAndViolatedConditions.getKey();
                    final List<PolicyCondition> violatedConditions = policyAndViolatedConditions.getValue();

                    if ((policy.getOperator() == Policy.Operator.ANY && !violatedConditions.isEmpty())
                            || (policy.getOperator() == Policy.Operator.ALL && violatedConditions.size() == policy.getPolicyConditions().size())) {
                        // TODO: Only a single violation should be raised, and instead multiple matched conditions
                        //   should be associated with it. Keeping the existing behavior in order to avoid having to
                        //   touch too much persistence and REST API code.
                        return violatedConditions.stream()
                                .map(condition -> {
                                    final var violation = new PolicyViolation();
                                    violation.setType(condition.getViolationType());
                                    // Note: violation.setComponent is intentionally omitted here,
                                    // because the component must be an object attached to the persistence
                                    // context. We don't have that at this point, we'll add it later.
                                    violation.setPolicyCondition(condition);
                                    violation.setTimestamp(new Date());
                                    return violation;
                                });
                    }

                    return Stream.empty();
                })
                .filter(Objects::nonNull)
                .toList();
    }

    private static org.dependencytrack.proto.policy.v1.Component mapToProto(final ComponentProjection projection,
                                                                            final Map<Long, org.dependencytrack.proto.policy.v1.License> protoLicenseById) {
        final org.dependencytrack.proto.policy.v1.Component.Builder componentBuilder =
                org.dependencytrack.proto.policy.v1.Component.newBuilder()
                        .setUuid(trimToEmpty(projection.uuid))
                        .setGroup(trimToEmpty(projection.group))
                        .setName(trimToEmpty(projection.name))
                        .setVersion(trimToEmpty(projection.version))
                        .setClassifier(trimToEmpty(projection.classifier))
                        .setCpe(trimToEmpty(projection.cpe))
                        .setPurl(trimToEmpty(projection.purl))
                        .setSwidTagId(trimToEmpty(projection.swidTagId))
                        .setIsInternal(Optional.ofNullable(projection.internal).orElse(false))
                        .setLicenseName(trimToEmpty(projection.licenseName))
                        .setLicenseExpression(trimToEmpty(projection.licenseExpression))
                        .setMd5(trimToEmpty(projection.md5))
                        .setSha1(trimToEmpty(projection.sha1))
                        .setSha256(trimToEmpty(projection.sha256))
                        .setSha384(trimToEmpty(projection.sha384))
                        .setSha512(trimToEmpty(projection.sha512))
                        .setSha3256(trimToEmpty(projection.sha3_256))
                        .setSha3384(trimToEmpty(projection.sha3_384))
                        .setSha3512(trimToEmpty(projection.sha3_512))
                        .setBlake2B256(trimToEmpty(projection.blake2b_256))
                        .setBlake2B384(trimToEmpty(projection.blake2b_384))
                        .setBlake2B512(trimToEmpty(projection.blake2b_512))
                        .setBlake3(trimToEmpty(projection.blake3));
        Optional.ofNullable(projection.latestVersion).ifPresent(componentBuilder::setLatestVersion);
        Optional.ofNullable(projection.publishedAt).map(Timestamps::fromDate).ifPresent(componentBuilder::setPublishedAt);
        if (projection.resolvedLicenseId != null && projection.resolvedLicenseId > 0) {
            final org.dependencytrack.proto.policy.v1.License protoLicense = protoLicenseById.get(projection.resolvedLicenseId);
            if (protoLicense != null) {
                componentBuilder.setResolvedLicense(protoLicenseById.get(projection.resolvedLicenseId));
            } else {
                LOGGER.warn("Component with ID %d refers to license with ID %d, but no license with that ID was found"
                        .formatted(projection.id, projection.resolvedLicenseId));
            }
        }

        return componentBuilder.build();
    }

    private static org.dependencytrack.proto.policy.v1.License mapToProto(final LicenseProjection projection) {
        final org.dependencytrack.proto.policy.v1.License.Builder licenseBuilder =
                org.dependencytrack.proto.policy.v1.License.newBuilder()
                        .setUuid(trimToEmpty(projection.uuid))
                        .setId(trimToEmpty(projection.licenseId))
                        .setName(trimToEmpty(projection.name));
        Optional.ofNullable(projection.isOsiApproved).ifPresent(licenseBuilder::setIsOsiApproved);
        Optional.ofNullable(projection.isFsfLibre).ifPresent(licenseBuilder::setIsFsfLibre);
        Optional.ofNullable(projection.isDeprecatedId).ifPresent(licenseBuilder::setIsDeprecatedId);
        Optional.ofNullable(projection.isCustomLicense).ifPresent(licenseBuilder::setIsCustom);

        if (projection.licenseGroupsJson != null) {
            try {
                final ArrayNode groupsArray = OBJECT_MAPPER.readValue(projection.licenseGroupsJson, ArrayNode.class);
                for (final JsonNode groupNode : groupsArray) {
                    licenseBuilder.addGroups(org.dependencytrack.proto.policy.v1.License.Group.newBuilder()
                            .setUuid(Optional.ofNullable(groupNode.get("uuid")).map(JsonNode::asText).orElse(""))
                            .setName(Optional.ofNullable(groupNode.get("name")).map(JsonNode::asText).orElse(""))
                            .build());
                }
            } catch (JacksonException e) {
                LOGGER.warn("Failed to parse license groups from %s for license %s"
                        .formatted(projection.licenseGroupsJson, projection.id), e);
            }
        }

        return licenseBuilder.build();
    }

    private static final TypeReference<List<VulnerabilityAlias>> VULNERABILITY_ALIASES_TYPE_REF = new TypeReference<>() {
    };

    private static org.dependencytrack.proto.policy.v1.Vulnerability mapToProto(final VulnerabilityProjection projection) {
        final org.dependencytrack.proto.policy.v1.Vulnerability.Builder builder =
                org.dependencytrack.proto.policy.v1.Vulnerability.newBuilder()
                        .setUuid(trimToEmpty(projection.uuid))
                        .setId(trimToEmpty(projection.vulnId))
                        .setSource(trimToEmpty(projection.source))
                        .setCvssv2Vector(trimToEmpty(projection.cvssV2Vector))
                        .setCvssv3Vector(trimToEmpty(projection.cvssV3Vector))
                        .setCvssv4Vector(trimToEmpty(projection.cvssV4Vector))
                        .setOwaspRrVector(trimToEmpty(projection.owaspRrVector));
        Optional.ofNullable(projection.cvssV2BaseScore).map(BigDecimal::doubleValue).ifPresent(builder::setCvssv2BaseScore);
        Optional.ofNullable(projection.cvssV2ImpactSubScore).map(BigDecimal::doubleValue).ifPresent(builder::setCvssv2ImpactSubscore);
        Optional.ofNullable(projection.cvssV2ExploitabilitySubScore).map(BigDecimal::doubleValue).ifPresent(builder::setCvssv2ExploitabilitySubscore);
        Optional.ofNullable(projection.cvssV3BaseScore).map(BigDecimal::doubleValue).ifPresent(builder::setCvssv3BaseScore);
        Optional.ofNullable(projection.cvssV3ImpactSubScore).map(BigDecimal::doubleValue).ifPresent(builder::setCvssv3ImpactSubscore);
        Optional.ofNullable(projection.cvssV3ExploitabilitySubScore).map(BigDecimal::doubleValue).ifPresent(builder::setCvssv3ExploitabilitySubscore);
        Optional.ofNullable(projection.cvssV4Score).map(BigDecimal::doubleValue).ifPresent(builder::setCvssv4Score);
        Optional.ofNullable(projection.owaspRrLikelihoodScore).map(BigDecimal::doubleValue).ifPresent(builder::setOwaspRrLikelihoodScore);
        Optional.ofNullable(projection.owaspRrTechnicalImpactScore).map(BigDecimal::doubleValue).ifPresent(builder::setOwaspRrTechnicalImpactScore);
        Optional.ofNullable(projection.owaspRrBusinessImpactScore).map(BigDecimal::doubleValue).ifPresent(builder::setOwaspRrBusinessImpactScore);
        Optional.ofNullable(projection.epssScore).map(BigDecimal::doubleValue).ifPresent(builder::setEpssScore);
        Optional.ofNullable(projection.epssPercentile).map(BigDecimal::doubleValue).ifPresent(builder::setEpssPercentile);
        Optional.ofNullable(projection.created).map(Timestamps::fromDate).ifPresent(builder::setCreated);
        Optional.ofNullable(projection.published).map(Timestamps::fromDate).ifPresent(builder::setPublished);
        Optional.ofNullable(projection.updated).map(Timestamps::fromDate).ifPresent(builder::setUpdated);
        Optional.ofNullable(projection.cwes)
                .map(StringUtils::trimToNull)
                .filter(Objects::nonNull)
                .map(new CollectionIntegerConverter()::convertToAttribute)
                .ifPresent(builder::addAllCwes);

        // Workaround for https://github.com/DependencyTrack/dependency-track/issues/2474.
        final Severity severity = VulnerabilityUtil.getSeverity(projection.severity,
                projection.cvssV2BaseScore,
                projection.cvssV3BaseScore,
                projection.cvssV4Score,
                projection.owaspRrLikelihoodScore,
                projection.owaspRrTechnicalImpactScore,
                projection.owaspRrBusinessImpactScore);
        builder.setSeverity(severity.name());

        if (projection.aliasesJson != null) {
            try {
                OBJECT_MAPPER.readValue(projection.aliasesJson, VULNERABILITY_ALIASES_TYPE_REF).stream()
                        .flatMap(CelPolicyEngine::mapToProto)
                        .distinct()
                        .forEach(builder::addAliases);
            } catch (JacksonException e) {
                LOGGER.warn("Failed to parse aliases from %s for vulnerability %d"
                        .formatted(projection.aliasesJson, projection.id), e);
            }
        }

        return builder.build();
    }

    private static Stream<Vulnerability.Alias> mapToProto(final VulnerabilityAlias alias) {
        return alias.getAllBySource().entrySet().stream()
                .map(aliasEntry -> Vulnerability.Alias.newBuilder()
                        .setSource(aliasEntry.getKey().name())
                        .setId(aliasEntry.getValue())
                        .build());
    }

    /**
     * Evaluate policy operators for crypto conditions specifically.
     * <p>
     * For policies with ALL operator that have both component and crypto conditions,
     * only crypto conditions are counted for the ALL requirement on the crypto side.
     * For ANY operator, any single crypto condition match suffices.
     */
    private static List<PolicyViolation> evaluateCryptoPolicyOperators(final Collection<PolicyCondition> conditionsViolated) {
        final Map<Policy, List<PolicyCondition>> violatedConditionsByPolicy = conditionsViolated.stream()
                .collect(Collectors.groupingBy(PolicyCondition::getPolicy));

        return violatedConditionsByPolicy.entrySet().stream()
                .flatMap(policyAndViolatedConditions -> {
                    final Policy policy = policyAndViolatedConditions.getKey();
                    final List<PolicyCondition> violatedConditions = policyAndViolatedConditions.getValue();

                    // Count only crypto conditions in this policy for ALL operator evaluation.
                    final long cryptoConditionCount = policy.getPolicyConditions().stream()
                            .filter(c -> CRYPTO_SUBJECTS.contains(c.getSubject()))
                            .count();

                    if ((policy.getOperator() == Policy.Operator.ANY && !violatedConditions.isEmpty())
                            || (policy.getOperator() == Policy.Operator.ALL && violatedConditions.size() == cryptoConditionCount)) {
                        return violatedConditions.stream()
                                .map(condition -> {
                                    final var violation = new PolicyViolation();
                                    violation.setType(condition.getViolationType());
                                    violation.setPolicyCondition(condition);
                                    violation.setTimestamp(new Date());
                                    return violation;
                                });
                    }

                    return Stream.empty();
                })
                .filter(Objects::nonNull)
                .toList();
    }

    static CryptoAsset mapToProto(final CryptoAssetProjection projection) {
        final CryptoAsset.Builder builder = CryptoAsset.newBuilder()
                .setUuid(trimToEmpty(projection.uuid))
                .setName(trimToEmpty(projection.name))
                .setAssetType(trimToEmpty(projection.assetType));
        Optional.ofNullable(projection.oid).ifPresent(builder::setOid);
        Optional.ofNullable(projection.description).ifPresent(builder::setDescription);

        // Algorithm sub-entity
        if (projection.algPrimitive != null || projection.algMode != null || projection.algPadding != null
                || projection.algParameterSetIdentifier != null || projection.algCurve != null
                || projection.algClassicalSecurityLevel != null || projection.algNistQuantumSecurityLevel != null) {
            final CryptoAlgorithm.Builder algBuilder = CryptoAlgorithm.newBuilder();
            Optional.ofNullable(projection.algPrimitive).ifPresent(algBuilder::setPrimitive);
            Optional.ofNullable(projection.algMode).ifPresent(algBuilder::setAlgorithmMode);
            Optional.ofNullable(projection.algPadding).ifPresent(algBuilder::setPadding);
            Optional.ofNullable(projection.algParameterSetIdentifier).ifPresent(algBuilder::setParameterSetIdentifier);
            Optional.ofNullable(projection.algCurve).ifPresent(algBuilder::setCurve);
            Optional.ofNullable(projection.algClassicalSecurityLevel).ifPresent(algBuilder::setClassicalSecurityLevel);
            Optional.ofNullable(projection.algNistQuantumSecurityLevel).ifPresent(algBuilder::setNistQuantumSecurityLevel);
            builder.setAlgorithm(algBuilder);
        }

        // Certificate sub-entity
        if (projection.certSubjectName != null || projection.certIssuerName != null
                || projection.certNotValidBefore != null || projection.certNotValidAfter != null
                || projection.certSignatureAlgorithmRef != null) {
            final CryptoCertificate.Builder certBuilder = CryptoCertificate.newBuilder();
            Optional.ofNullable(projection.certSubjectName).ifPresent(certBuilder::setSubjectName);
            Optional.ofNullable(projection.certIssuerName).ifPresent(certBuilder::setIssuerName);
            Optional.ofNullable(projection.certNotValidBefore).map(Timestamps::fromDate).ifPresent(certBuilder::setNotValidBefore);
            Optional.ofNullable(projection.certNotValidAfter).map(Timestamps::fromDate).ifPresent(certBuilder::setNotValidAfter);
            Optional.ofNullable(projection.certSignatureAlgorithmRef).ifPresent(certBuilder::setSignatureAlgorithmRef);
            builder.setCertificate(certBuilder);
        }

        // Protocol sub-entity
        if (projection.protoType != null || projection.protoVersion != null || projection.protoCipherSuites != null) {
            final CryptoProtocol.Builder protoBuilder = CryptoProtocol.newBuilder();
            Optional.ofNullable(projection.protoType).ifPresent(protoBuilder::setProtocolType);
            Optional.ofNullable(projection.protoVersion).ifPresent(protoBuilder::setProtocolVersion);
            Optional.ofNullable(projection.protoCipherSuites).ifPresent(protoBuilder::setCipherSuites);
            builder.setProtocol(protoBuilder);
        }

        // Related material sub-entity
        if (projection.rmType != null || projection.rmSize != null || projection.rmFormat != null || projection.rmAlgorithmRef != null) {
            final CryptoRelatedMaterial.Builder rmBuilder = CryptoRelatedMaterial.newBuilder();
            Optional.ofNullable(projection.rmType).ifPresent(rmBuilder::setType);
            Optional.ofNullable(projection.rmSize).ifPresent(rmBuilder::setSize);
            Optional.ofNullable(projection.rmFormat).ifPresent(rmBuilder::setFormat);
            Optional.ofNullable(projection.rmAlgorithmRef).ifPresent(rmBuilder::setAlgorithmRef);
            builder.setRelatedMaterial(rmBuilder);
        }

        return builder.build();
    }

}
