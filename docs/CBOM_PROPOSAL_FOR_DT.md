# Proposal: CBOM Support for Dependency-Track

## Cryptographic Bill of Materials: Post-Quantum Readiness & Export Control

## 1. Why CBOM Matters for Dependency-Track

Dependency-Track has established itself as the leading open-source platform for Software Bill of Materials (SBOM) management. We believe extending it with **Cryptographic Bill of Materials (CBOM)** support represents a natural and high-value evolution that serves two urgent, converging regulatory drivers:

### 1.1 Post-Quantum Cryptography Migration

NIST finalized the first post-quantum cryptographic standards in 2024 (FIPS 203, 204, 205). Organizations worldwide now face a multi-year migration away from RSA, ECDSA, and other quantum-vulnerable algorithms. To plan this migration, they must first **inventory every cryptographic algorithm in their software supply chain**, which is the exact capability a CBOM provides.

Key compliance frameworks driving this:
- **NSA CNSA 2.0** (Commercial National Security Algorithm Suite) mandates quantum-resistant algorithms for national security systems by 2030-2035
- **NIST SP 800-131A Rev 2** deprecates specific algorithm/key-size combinations
- **Executive Order 14028** and subsequent OMB memoranda require federal agencies to inventory cryptographic assets

### 1.2 Export Control (ECCN Classification)

Cryptographic software is subject to export controls under the **Wassenaar Arrangement** and national regulations (US EAR Category 5 Part 2, EU Dual-Use Regulation). Organizations that distribute software internationally must:

- Identify which cryptographic algorithms their software implements
- Determine the applicable **Export Control Classification Number (ECCN)**
- File license exceptions (e.g., EAR Section 740.17 for mass-market encryption)

Today, this is done manually through audits. A CBOM attached to the SBOM automates this inventory, reducing compliance cost and risk.

### 1.3 Why Dependency-Track Is the Right Home

CBOMs are not a separate concept from SBOMs. They are **CycloneDX BOMs** with `cryptographic-asset` components and `cryptoProperties`. CycloneDX 1.6 already defines the schema. This means:

- The same upload flow handles both SBOMs and CBOMs
- The same project/portfolio model applies
- The same policy engine can enforce crypto-specific rules
- Users already comfortable with DT's vulnerability triage can apply the same workflow to crypto governance

For the DT community, CBOM support would:
- **Expand the user base** to include cryptography compliance teams (post-quantum, export control, FIPS validation)
- **Increase DT's relevance** as organizations adopt CycloneDX 1.6+ with crypto extensions
- **Differentiate DT** from commercial alternatives that lack native CBOM handling


## 2. What We Propose

We propose adding first-class CBOM support to Dependency-Track. This section provides a detailed technical design based on a proof-of-concept implementation we have built against v4.13.6. The PoC is functional and covers ingestion, storage, API, UI, policy engine, metrics, and export. Below we describe what the full, production-quality implementation should include, incorporating lessons from the PoC and additional requirements not covered in it.


## 3. Detailed Technical Design

### 3.1 Data Model

#### 3.1.1 Core Entities

Seven new JDO model classes, all `@PersistenceCapable` and registered in `persistence.xml`:

| Entity | Purpose | Key Fields |
|---|---|---|
| `CryptoAsset` | Core entity linking a crypto component to a project | `project` (FK), `name`, `bomRef`, `assetType` (enum), `oid`, `description`, `occurrences` (JSON) |
| `CryptoAssetAlgorithm` | Algorithm-specific properties | `primitive` (enum), `mode`, `padding`, `parameterSetIdentifier`, `curve`, `cryptoFunctions` (JSON), `classicalSecurityLevel`, `nistQuantumSecurityLevel` |
| `CryptoAssetCertificate` | Certificate-specific properties | `subjectName`, `issuerName`, `notValidBefore`, `notValidAfter`, `signatureAlgorithmRef`, `subjectPublicKeyRef`, `certificateFormat`, `certificateExtension` |
| `CryptoAssetProtocol` | Protocol-specific properties | `type`, `version`, `cipherSuites` (JSON) |
| `CryptoAssetRelatedMaterial` | Key material metadata (never raw keys) | `type` (enum), `size`, `format`, `algorithmRef` |
| `CryptoAssetAnalysis` | Triage/audit decisions per crypto asset | `state`, `justification`, `response`, `details`, `comment`, `suppressed` |
| `CryptoAssetMetrics` | Per-project crypto metrics (14 counters) | `totalAssets`, `algorithmCount`, `quantumSafe`, `quantumVulnerable`, `expiredCertificates`, `policyViolations`, etc. |

#### 3.1.2 Enums

| Enum | Values |
|---|---|
| `CryptoAssetType` | `ALGORITHM`, `PROTOCOL`, `CERTIFICATE`, `RELATED_CRYPTO_MATERIAL` |
| `CryptoPrimitive` | `HASH`, `SIGNATURE`, `BLOCK_CIPHER`, `STREAM_CIPHER`, `AE`, `MAC`, `KEY_AGREE`, `KEY_ENCAPSULATION`, `KDF`, `PKE`, `OTHER` |
| `RelatedCryptoMaterialType` | `SECRET_KEY`, `PUBLIC_KEY`, `PRIVATE_KEY`, `KEY_PAIR`, `CERTIFICATE`, `CIPHERTEXT`, `SIGNATURE`, `DIGEST`, `INITIALIZATION_VECTOR`, `NONCE`, `SEED`, `SALT`, `SHARED_SECRET`, `TAG`, `ADDITIONAL_DATA`, `PASSWORD`, `CREDENTIAL`, `TOKEN`, `OTHER`, `UNKNOWN` |
| `CryptoAssetAnalysisState` | See Section 3.7 (Crypto Asset Triage) |

#### 3.1.3 Database Indexes

At minimum: `CRYPTOASSET_PROJECT_ID_IDX` on the project FK. Consider additional indexes on `assetType` and `bomRef` for filtered queries and cross-reference resolution.

### 3.2 Deterministic Identifiers for Crypto Assets

#### 3.2.1 The Problem with Random UUIDs

The current CycloneDX convention uses random UUIDs for `bom-ref` (e.g., `bom-ref="3e671687-395b-41f5-a30f-a58921a69b79"`). For software components this works well because each component instance is unique. For cryptographic assets, however, the same algorithm appears across many projects and BOM uploads. Using random UUIDs means:

- Two CBOMs declaring "AES-256-GCM" produce different `bom-ref` values, making correlation impossible
- Re-uploading the same CBOM generates new IDs, breaking audit trails
- Portfolio-level deduplication requires fuzzy string matching instead of ID equality

#### 3.2.2 CycloneDX Cryptography Definitions Registry

The CycloneDX project maintains a [cryptography-defs.json](https://github.com/CycloneDX/specification/blob/master/schema/cryptography-defs.json) registry that defines standardized naming patterns for algorithm families:

```
Family: AES      -> Pattern: AES[-(128|192|256)][-(ECB|CBC|CTR|CFB|OFB|GCM|CCM|...)]
Family: RSA-OAEP -> Pattern: RSA-OAEP[-{hashAlgorithm}][-{maskGenAlgorithm}][-{keyLength}]
Family: EdDSA    -> Pattern: Ed(25519|448)[-(ph|ctx)]
```

These patterns provide **canonical algorithm names** (e.g., `AES-256-GCM`, `RSA-OAEP-SHA256-2048`). However, they only cover algorithms, not certificates, protocols, or related material. They also do not define an identifier scheme; they define how to *name* an algorithm consistently.

#### 3.2.3 Proposed Approach: Content-Addressable `bom-ref`

We propose generating deterministic `bom-ref` values by hashing the canonical properties of each crypto asset. The CycloneDX specification explicitly allows `bom-ref` to be **any string** (not restricted to UUID format), so this is spec-compliant.

**Construction rule:** `crypto-{assetType}-{sha256hex16}` where the SHA-256 input depends on the asset type:

**SHA-256 inputs** (all values canonical, sorted, lowercased):

- **Algorithm:** `algorithm:{name}:{primitive}:{mode}:{padding}:{paramSetId}:{curve}:{oid}`
- **Certificate:** `certificate:{subject}:{issuer}:{notBefore}:{notAfter}:{format}`
- **Protocol:** `protocol:{type}:{version}`
- **Related Material:** `related-material:{type}:{algorithmRef}:{format}:{size}`

Example for AES-256-GCM:
```
Input:  "algorithm:aes-256-gcm:block_cipher:gcm::::"
SHA256: a1b2c3d4e5f6...
bom-ref: "crypto-algorithm-a1b2c3d4e5f67890"
```

**Benefits:**
- Same algorithm always gets the same `bom-ref` across all projects and uploads
- Portfolio-level deduplication is trivial (group by `bom-ref`)
- Audit trails survive re-uploads
- CycloneDX standardized algorithm names (from `cryptography-defs.json`) can be used as the `name` input, ensuring consistency

**Why not just reuse the CycloneDX pattern string directly as `bom-ref`?** Two reasons: (1) patterns cover only algorithms, not other asset types; (2) two assets with the same algorithm name but different OIDs or parameter sets must produce different identifiers. The hash captures the full property tuple.

**Fallback:** If properties are sparse (e.g., a BOM lists only `name: "AES"` without mode/padding), the hash still works; it simply groups all "AES" entries into one identifier. CBOM generators should be encouraged to use fully-qualified names from `cryptography-defs.json`.

### 3.3 Ingestion Pipeline

#### 3.3.1 Parser

Extend `ModelConverter.java` with a `convertCryptoAssetsFromJson(byte[] bomBytes, Project project)` method that:

1. Parses raw BOM JSON (the CycloneDX Java library does not yet fully support `cryptographic-asset` component types)
2. Filters components where `type == "cryptographic-asset"`
3. Extracts `cryptoProperties` and maps them to type-specific sub-entities
4. Resolves `bom-ref` cross-references (`signatureAlgorithmRef`, `subjectPublicKeyRef`, `algorithmRef`)
5. **Strips sensitive material:** if `relatedCryptoMaterialProperties.value` is present, removes it before persistence and logs a warning

#### 3.3.2 BOM Upload Integration

Add `processCryptoAssets(ctx)` to `BomUploadProcessingTask`, called after main component processing:

- Runs in its own transaction to isolate crypto processing failures from SBOM ingestion
- Idempotent: deletes all existing crypto assets for the project, then re-creates from new BOM (clean-slate approach)
- Triggers `CryptoMetricsUpdateEvent` after successful persistence
- Returns early with a debug log when no `cryptographic-asset` components are found (zero impact on non-CBOM uploads)

### 3.4 REST API

#### 3.4.1 Crypto Asset Endpoints

All require `VIEW_CRYPTO_ASSETS` unless noted.

| Endpoint | Description |
|---|---|
| GET /v1/crypto-asset/project/{uuid} | List assets for project (paginated, filterable) |
| GET /v1/crypto-asset/{uuid} | Get single crypto asset |
| GET /v1/crypto-asset/{uuid}/algorithm | Algorithm detail |
| GET /v1/crypto-asset/{uuid}/certificate | Certificate detail |
| GET /v1/crypto-asset/{uuid}/protocol | Protocol detail |
| GET /v1/crypto-asset/{uuid}/related-material | Related material detail |
| DELETE /v1/crypto-asset/{uuid} | Delete asset (requires `PORTFOLIO_MANAGEMENT`) |

#### 3.4.2 Analysis Endpoints

| Endpoint | Description |
|---|---|
| GET /v1/crypto-analysis/project/{uuid} | List analyses (`VIEW_CRYPTO_ASSETS`) |
| PUT /v1/crypto-analysis | Create/update analysis (`CRYPTO_ANALYSIS`) |
| DELETE /v1/crypto-analysis/{uuid} | Delete analysis (`CRYPTO_ANALYSIS`) |

#### 3.4.3 Metrics Endpoints

| Endpoint | Description |
|---|---|
| GET /v1/metrics/crypto/project/{uuid} | Project crypto metrics |
| GET /v1/metrics/crypto/portfolio | Portfolio aggregated metrics |

#### 3.4.4 Export Endpoints

| Endpoint | Description |
|---|---|
| GET /v1/bom/cbom/project/{uuid} | Export project CBOM (CycloneDX 1.6 JSON) |
| GET /v1/bom/cbom/component/{uuid} | Export component scoped CBOM |
| POST /v1/bom/cbom/portfolio | Export portfolio CBOM |

All export endpoints require `VIEW_CRYPTO_ASSETS`. Query parameters: `includeDependencies`, `includeAnalysis`, `includePolicyViolations`, `minify`.

### 3.5 Policy Engine

#### 3.5.1 New Policy Condition Subjects

9 new subjects added to `PolicyCondition.Subject`:

| Subject | Evaluates | Operators |
|---|---|---|
| CRYPTO_ALGORITHM_NAME | Asset name | IS, IS_NOT, MATCHES |
| CRYPTO_ALGORITHM_PRIMITIVE | Primitive enum | IS, IS_NOT, MATCHES |
| CRYPTO_ALGORITHM_PARAMETER_SET | Parameter set ID | IS, IS_NOT, MATCHES |
| CRYPTO_QUANTUM_SECURITY | NIST quantum security level | All numeric |
| CRYPTO_CLASSICAL_STRENGTH | Classical security level (bits) | All numeric |
| CRYPTO_PROTOCOL_VERSION | Combined "type version" string | IS, IS_NOT, MATCHES |
| CRYPTO_CERTIFICATE_EXPIRY | Days until expiry | All numeric |
| CRYPTO_CERTIFICATE_ALGORITHM | Signature algorithm ref | IS, IS_NOT, MATCHES |
| CRYPTO_MATERIAL_TYPE | Material type enum | IS, IS_NOT, MATCHES |

Each subject is handled by a dedicated evaluator class (e.g., `CryptoAlgorithmPolicyEvaluator` for the algorithm subjects, `CryptoQuantumPolicyEvaluator` for quantum/classical strength).

#### 3.5.2 Pre-Configured Policy Templates

The following policies should be shipped as seed data, ready for users to enable:

| Policy | Condition | Use Case |
|---|---|---|
| Quantum Vulnerable | CRYPTO_QUANTUM_SECURITY < 1 | Post-quantum migration |
| Weak Classical Strength | CRYPTO_CLASSICAL_STRENGTH < 128 | Security hygiene |
| Legacy Algorithms | CRYPTO_ALGORITHM_NAME matches MD5, SHA1, DES, 3DES, RC4 | Deprecated algorithm detection |
| Expiring Certs (30d) | CRYPTO_CERTIFICATE_EXPIRY < 30 | Certificate lifecycle |
| Legacy TLS | CRYPTO_PROTOCOL_VERSION matches TLS 1.0/1.1 | TLS compliance |
| Non-CNSA 2.0 | CRYPTO_ALGORITHM_NAME matches non-CNSA regex | CNSA 2.0 compliance |

#### 3.5.3 Violation Types

We recommend adding `SECURITY_CRYPTO` and `OPERATIONAL_CRYPTO` to `PolicyViolation.Type` to distinguish crypto policy violations from vulnerability-related security violations. This enables filtered views and reporting that separate crypto governance from vulnerability management.

### 3.6 UI

#### 3.6.1 Navigation

- New top-level sidebar entry: **Crypto Assets** (lock icon), gated by `VIEW_CRYPTO_ASSETS` permission
- Route: `/cryptoAssets`

#### 3.6.2 Views

| View | Description |
|---|---|
| **Crypto Assets Overview** | Top-level list with type filter (Algorithm/Protocol/Certificate/Related Material), color-coded badges for type and quantum status, server-side pagination |
| **Project Crypto Tab** | New tab on project page showing project-scoped crypto assets with CBOM export button |
| **Algorithm Sub-View** | Filtered view showing only algorithms with primitive, mode, key size, quantum level columns |
| **Protocol Sub-View** | Filtered view showing protocols with type, version, cipher suite summary |
| **Crypto Audit View** | Analysis/triage decisions for crypto assets (see Section 3.7) |
| **Crypto Policy Violations View** | Crypto-specific policy violations with triage (see Section 3.8) |
| **Dashboard Widgets** | Crypto overview cards on project dashboard: totals by type, quantum readiness pie chart, expiring certificates count |

### 3.7 Crypto Asset Triage

#### 3.7.1 Motivation

When a CBOM is ingested, all detected cryptographic components appear in the inventory. However, not all of them are necessarily *in active use* in the software. For example:

- A library may ship with support for multiple algorithms, but the application only configures one
- A dependency may include deprecated cipher suites that are compiled-in but never negotiated
- A certificate bundled in a container image may belong to a test environment

Users need the ability to **triage** each detected crypto component to indicate whether it is actively used, irrelevant, or still under investigation. This is directly analogous to how DT handles vulnerability triage today.

#### 3.7.2 Proposed Analysis States

We propose the following states for crypto asset analysis, inspired by but distinct from DT's existing vulnerability analysis states:

| State | Meaning | When to Use |
|---|---|---|
| `NOT_SET` | No decision made yet | Default for all newly ingested assets |
| `IN_TRIAGE` | Under investigation | Analyst is reviewing whether the asset is in use |
| `IN_USE` | Confirmed actively used | The crypto component is confirmed to be exercised at runtime |
| `NOT_IN_USE` | Confirmed not used | Present in code/dependencies but not reachable or configured |
| `FALSE_POSITIVE` | Detection was incorrect | CBOM generator incorrectly identified this as a crypto asset |
| `RESOLVED` | Issue addressed | Deprecated algorithm has been replaced, expired cert renewed, etc. |

**Justification field** (free text or enum) to record *why* the analyst made that decision. Examples:
- "Only AES-256-GCM is configured in production; AES-128-CBC is unused legacy code"
- "This certificate is for the test environment only"

#### 3.7.3 Architecture

This should follow the existing `Analysis` / `AnalysisComment` pattern used for vulnerability triage:

| DT Vulnerability Triage | Crypto Asset Triage (Proposed) |
|---|---|
| `Analysis` model | `CryptoAssetAnalysis` model |
| `AnalysisState` enum | `CryptoAssetAnalysisState` enum (states above) |
| `AnalysisComment` model | `CryptoAssetAnalysisComment` model |
| `AnalysisJustification` enum | `CryptoAssetJustification` enum (optional, see below) |
| `AnalysisResource` REST | `CryptoAnalysisResource` REST |
| `VULNERABILITY_ANALYSIS` permission | `CRYPTO_ANALYSIS` permission |

**Key implementation details:**

- **Composite unique constraint** on (`project`, `cryptoAsset`) ensures one analysis record per asset per project
- **Immutable audit trail** via `CryptoAssetAnalysisComment`: every state change auto-generates a comment with timestamp and commenter (e.g., `"IN_TRIAGE -> IN_USE"`)
- **Suppression flag** (`suppressed` boolean) allows hiding triaged assets from active counts without deleting the record
- **REST API** follows the `PUT /v1/crypto-analysis` upsert pattern, where null fields in the request preserve existing values

#### 3.7.4 Optional: Structured Justification Enum

For organizations that need structured triage reasons (e.g., for auditors), an optional `CryptoAssetJustification` enum:

```
CODE_NOT_REACHABLE          Algorithm in dependency but execution path not reachable
CONFIGURATION_DISABLED      Algorithm compiled in but disabled via configuration
TEST_ENVIRONMENT_ONLY       Certificate/key used only in non-production environments
DEPENDENCY_MANAGED          Crypto usage managed by upstream dependency, not directly controlled
MIGRATION_PLANNED           Deprecated algorithm acknowledged, migration scheduled
ACCEPTED_RISK               Known weak algorithm accepted per risk assessment
```

### 3.8 Policy Violation Triage

#### 3.8.1 Motivation

Crypto policies (Section 3.5) will inevitably generate false positives. For example:

- A "Quantum-Vulnerable Algorithms" policy flags `RSA-2048` in a non-production test tool
- A "Legacy TLS" policy flags `TLS 1.1` support in a library that also supports `TLS 1.3` and only negotiates the latter
- A "Weak Classical Strength" policy flags an algorithm that is only used for non-security-critical checksumming

Users must be able to **triage these violations** without disabling the policy entirely. This is not a new concept. DT already supports it for license and security policy violations via the `ViolationAnalysis` model.

#### 3.8.2 Proposed Approach: Reuse Existing ViolationAnalysis

Crypto policy violations should use the **existing `ViolationAnalysis` / `ViolationAnalysisState` mechanism** without modification. This is the correct approach because:

1. **Crypto violations are `PolicyViolation` objects**, created by the policy engine just like license or security violations
2. **The existing triage states apply directly:**

| `ViolationAnalysisState` | Meaning for Crypto Violations |
|---|---|
| `NOT_SET` | No decision on this violation yet |
| `APPROVED` | Violation acknowledged and accepted (e.g., risk accepted, exception granted) |
| `REJECTED` | Violation confirmed as real; must be remediated |

3. **The existing UI already works.** The policy violations view shows all violation types with their analysis states. Adding `SECURITY_CRYPTO` / `OPERATIONAL_CRYPTO` violation types automatically surfaces crypto violations in this view with full triage support.

4. **Audit trail is automatic.** `ViolationAnalysisComment` records all state transitions with timestamp and commenter.

#### 3.8.3 What Needs to Be Done

- No new models needed. The existing `ViolationAnalysis`, `ViolationAnalysisState`, and `ViolationAnalysisComment` classes handle everything.
- The `ViolationAnalysisResource` REST API (`PUT /v1/violation/analysis`) already supports triaging any `PolicyViolation` regardless of type.
- The only requirement is that crypto policy evaluators generate standard `PolicyViolation` objects (which they do), so the violation analysis machinery applies automatically.
- The UI should ensure crypto violations are clearly identifiable (via the `SECURITY_CRYPTO` type badge) so analysts can filter and triage them efficiently.

### 3.9 Permissions

Two new permissions:

| Permission | Description |
|---|---|
| `VIEW_CRYPTO_ASSETS` | View cryptographic asset inventory, analysis, and metrics |
| `CRYPTO_ANALYSIS` | Create/update/delete analysis decisions on crypto assets |

Policy management and violation analysis reuse the existing `POLICY_MANAGEMENT` and `POLICY_VIOLATION_ANALYSIS` permissions.

### 3.10 Metrics

#### 3.10.1 Per-Project Crypto Metrics (14 counters)

| Counter | Description |
|---|---|
| `totalAssets` | Total crypto assets |
| `algorithmCount` | Assets of type ALGORITHM |
| `protocolCount` | Assets of type PROTOCOL |
| `certificateCount` | Assets of type CERTIFICATE |
| `relatedMaterialCount` | Assets of type RELATED_CRYPTO_MATERIAL |
| `quantumSafe` | Algorithms with NIST quantum security level >= threshold |
| `quantumVulnerable` | Algorithms with quantum level < threshold |
| `quantumUnknown` | Algorithms with null/unknown quantum level |
| `classicalStrengthHigh` | Algorithms with classical level >= 192 bits |
| `classicalStrengthMedium` | Algorithms with 128 <= classical level < 192 |
| `classicalStrengthLow` | Algorithms with classical level < 128 bits |
| `expiredCertificates` | Certificates past `notValidAfter` |
| `expiringCertificates` | Certificates expiring within 30 days |
| `policyViolations` | Count of crypto-related policy violations |

#### 3.10.2 Metrics Task

`CryptoMetricsUpdateTask` subscribes to `CryptoMetricsUpdateEvent`, computes all counters, and persists with deduplication (only creates a new row when values change; otherwise updates `lastOccurrence`).

#### 3.10.3 Recommended Extensions

- Extend `ProjectMetrics` with summary crypto fields (`cryptoAssets`, `cryptoQuantumVulnerable`, `cryptoPolicyViolations`)
- Add portfolio-level crypto metrics aggregation
- Add triage state distribution to metrics (count of `IN_USE`, `NOT_IN_USE`, `IN_TRIAGE`, etc.)

### 3.11 CBOM Export

`CbomExportResource` generates CycloneDX 1.6 JSON with:

- `bomFormat: "CycloneDX"`, `specVersion: "1.6"`
- `serialNumber` as UUID URN (per CycloneDX spec requirement)
- `metadata.component` with project details
- `components[]` array where each entry has:
  - `type: "cryptographic-asset"`
  - `bom-ref` (deterministic, per Section 3.2)
  - `name`, `description`
  - `cryptoProperties` with all type-specific sub-properties
  - Optionally: analysis annotations, policy violation annotations

### 3.12 Security Considerations

| Concern | Mitigation |
|---|---|
| Private keys in BOM | Parser strips `relatedCryptoMaterialProperties.value` if present; logs warning; persists only metadata (type, size, format) |
| RBAC enforcement | All endpoints gated by `VIEW_CRYPTO_ASSETS` or `CRYPTO_ANALYSIS`; write operations require appropriate permissions |
| XSS in crypto names | Frontend uses `xssFilters.inHTMLData()` on all dynamic values |


## 4. Implementation Phases

We recommend a phased approach that delivers incremental value:

### Phase 1: Data Foundation (Database + Models)
- JDO model classes for all 7 entities + 5 enums
- `CryptoAssetQueryManager` with full CRUD
- `persistence.xml` registration
- Deterministic `bom-ref` generation utility
- **Success criteria:** >= 80% model test coverage; schema auto-creates correctly

### Phase 2: Ingestion Pipeline
- `ModelConverter` parser extension for `cryptographic-asset` components
- `BomUploadProcessingTask` integration
- Sensitive material stripping
- **Success criteria:** Sample CBOMs ingest correctly; non-CBOM BOMs unaffected

### Phase 3: REST API + Auth
- All CRUD, analysis, metrics, and export endpoints
- Permission enforcement
- OpenAPI annotations
- **Success criteria:** Full API coverage verified by integration tests

### Phase 4: Policy Engine
- 5 evaluators, 9 subjects
- Policy seed data / templates
- `SECURITY_CRYPTO` violation type
- **Success criteria:** Pre-configured policies detect weak algorithms, expiring certs with < 1% false negatives on curated test set

### Phase 5: UI
- Top-level Crypto Assets view with filtering
- Project-level crypto tab
- Crypto asset triage panel (analysis states, comments, suppression)
- Policy violation triage (reuses existing violation analysis UI)
- Dashboard widgets
- **Success criteria:** UX review sign-off; all views gated by permissions

### Phase 6: Metrics + Export Extensions
- Portfolio-level metrics
- Dashboard metrics endpoint
- Component-scope and portfolio-scope export
- Export query parameters (dependencies, analysis, violations, minify)


## 5. Effort Estimate

| Phase | Traditional (1 developer) | With AI-assisted development |
|---|---|---|
| Phase 1: Data Foundation | 1-2 weeks | 2-3 days |
| Phase 2: Ingestion | 1-2 weeks | 2-3 days |
| Phase 3: REST API | 1 week | 1-2 days |
| Phase 4: Policy Engine | 1-2 weeks | 2-3 days |
| Phase 5: UI | 2-3 weeks | 1-2 weeks |
| Phase 6: Metrics + Export | 1-2 weeks | 2-3 days |
| **Testing & Documentation** | 2-3 weeks | 1-2 weeks |
| **Total** | **10-16 weeks** | **4-6 weeks** |


## 6. Proof of Concept

We have built a working PoC against Dependency-Track v4.13.6 that implements Phases 1-5 (excluding some sub-views and dashboard widgets). The PoC includes:

- **24 new Java files** (models, enums, persistence, policy evaluators, REST resources, metrics task)
- **7 modified Java files** (QueryManager, PolicyCondition, PolicyEngine, Permissions, ModelConverter, BomUploadProcessingTask, persistence.xml)
- **2 new Vue components** + **7 modified frontend files**
- Full patches are available for review

The PoC demonstrates that CBOM support integrates cleanly into DT's existing architecture without disrupting SBOM workflows.


## 7. References

- [CycloneDX Specification - Cryptographic Assets](https://cyclonedx.org/capabilities/cbom/)
- [CycloneDX Cryptography Definitions Registry](https://github.com/CycloneDX/specification/blob/master/schema/cryptography-defs.json)
- [NIST Post-Quantum Cryptography Standards (FIPS 203, 204, 205)](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [NSA CNSA 2.0 Algorithm Suite](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)
- [EAR Category 5 Part 2 - Encryption Items](https://www.bis.doc.gov/index.php/policy-guidance/encryption)
- [IBM CBOMkit](https://github.com/IBM/cbomkit)
