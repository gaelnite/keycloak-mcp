# Keycloak 26.8.1 extension shortlist (reference deployment)

**Audit date: 2026-10-23.** Target: **Keycloak 26.8.1**, released **2026-10-13** (verified via GitHub releases; the docs version picker also lists 26.8.1). Deployment: rootless Podman, always-on, single laptop.

**26.8 is ~10 days old at audit time, so this list is deliberately strict.** A project is only `SAFE` if it publishes an artifact *built against 26.8*, a README claim on `main` is not enough. Where a project declares 26.8 but has not released since before it, it is `LIKELY`, not `SAFE`.

**Method per candidate:** GitHub `/releases` (tag + date + asset list), README compatibility statements/badges, `pom.xml` `<keycloak.version>` where published, Maven Central publish timestamps, and for the chosen set an actual download + `sha256` + provider-SPI inspection of each JAR.

## Verdict legend

| Verdict | Meaning |
|---|---|
| **SAFE** | Artifact published *against 26.8* and it is a drop-in provider (or an external tool that cannot affect runtime) |
| **LIKELY** | Declares 26.x (or 26.8 on `main` only) but the released artifact predates 26.8, expect it to work, test first |
| **RISKY** | No version declaration and ≥1.5 years without a release |
| **SKIP** | Not a runtime extension (testcontainers/helm/terraform/operator/ansible) |

## 1. Candidates

| Extension | ★ | Latest release (date) | Declared KC | Verdict |
|---|---|---|---|---|
| p2-inc/**keycloak-orgs** | 544 | 0.192, Maven Central 2026-10-14 | `pom.xml` `keycloak.version` = **26.8.0** | **SAFE but NOT shipped**: missing SCIM classes break `/admin/serverinfo` |
| p2-inc/**keycloak-magic-link** | 430 | 0.93, 2026-10-20 | `pom.xml` = **26.8.0** | **SAFE** |
| p2-inc/**keycloak-events** | 317 | 0.66, 2026-10-15 | `pom.xml` = **26.8.0** | **SAFE** |
| netzbegruenung/**keycloak-mfa-plugins** | 300 | v26.8.0-1, 2026-10-13 | version scheme is `<keycloak.version>-<counter>` → **built against 26.8.0** | **SAFE** |
| sventorben/**keycloak-restrict-client-auth** | 440 | v26.1.1, **2026-07-19** | README badge on `main` = **26.8.0**, but no release since July | **LIKELY** |
| sventorben/**keycloak-home-idp-discovery** | 341 | v26.2.2, **2026-07-19** | same: badge 26.8.0 on `main`, last release July | **LIKELY** |
| adorsys/**keycloak-config-cli** | 1212 | v6.5.1, 2026-05-22 | per-KC JARs stop at **26.5.5**; policy is "latest 4 releases" | **LIKELY** |
| MLukman/**PII-Data-Encryption** | 39 | v2.7, 2025-09-02 | "24.x and above"; README built against 26.3 | **LIKELY** |
| klausbetz/**apple-identity-provider** | 297 | 1.17.0, 2026-01-15 | compat table tops out at `25.0.0 < 26.2.3`; 1.17.0 not covered | **LIKELY** |
| anarsultanov/**keycloak-multi-tenancy** | 171 | 26.1.1, 2025-12-12 | mentions 24.0 | **LIKELY** |
| Nordix/**keycloak-secrets-vault-provider** | 12 | v1.1.0, 2026-08-14 | none; **no binary published** (0 release assets, absent from Maven Central) | **RISKY** |
| aerogear/**keycloak-metrics-spi** | 614 | 7.0.0, **2024-11-07** | none | **RISKY** |
| aznamier/**event-listener-rabbitmq** | 170 | 3.0.5, **2024-03-20** | "Keycloak 17+" only | **RISKY** |
| embesozzi/**openfga-event-publisher** | 61 | 1.1.1, **2024-06-29** | none | **RISKY** |
| iteratec/**kcwarden** | 135 | v0.18.1, 2026-06-10 | n/a, offline auditor, PyPI `kcwarden` 0.18.1, py≥3.11,<4 | **SAFE** (external) |

**Excluded as non-runtime:** `keycloak/terraform-provider-keycloak` (954★), `dasniko/testcontainers-keycloak` (464★), both helm charts, the ansible collection, `crossplane-contrib/provider-keycloak`, `epam/edp-keycloak-operator`, `keycloak-client/keycloak-client` (Python client). None of these load into the Keycloak runtime.

## 2. Recommended set for the MCP reference

Eight capabilities, each callable or observable by an MCP server. **5 build into the image today; 3 are external/optional.**

| # | Capability an MCP can expose | Extension | Verdict |
|---|---|---|---|
| 1 | Org/multi-tenancy CRUD | native Organizations (`/admin/realms/{realm}/organizations`) | native |
| 2 | Audit/event stream, webhooks | p2-inc/keycloak-events → listeners `ext-event-webhook`-class + `/realms/{realm}/events`, `/webhooks` REST | SAFE |
| 3 | Passwordless login flow | p2-inc/keycloak-magic-link → `MagicLinkAuthenticatorFactory`, `/realms/{realm}/magic-link` | SAFE |
| 4 | MFA enforcement policy | netzbegruenung/enforce-mfa, `EnforceMfaAuthenticatorFactory`, `ConditionalEnforceMfaAuthenticatorFactory`, `MfaCredentialConditionFactory` (verified by unzipping the JAR) | SAFE |
| 5 | Second factor (app / email / SMS / trusted device) | netzbegruenung app-, email-, sms-, trusted-device-authenticator | SAFE |
| 6 | Config-as-code (realm YAML/JSON apply) | adorsys/keycloak-config-cli, **external container**, speaks Admin REST | LIKELY |
| 7 | Config auditing (drift/misconfig scan) | iteratec/kcwarden, **external CLI**, `pip install kcwarden` | SAFE |
| 8 | Metrics | **native**: Keycloak 26.x ships `--metrics-enabled` + `/metrics` (see `/server/all-config`), use this instead of metrics-spi | built-in |

Optional 9th: `sventorben/keycloak-restrict-client-auth` (client-level access policy, a good "authorization decision" endpoint for an MCP), LIKELY, test before trusting.

## 3. The Organizations question (asked explicitly)

**Keycloak 26.x has native Organizations built in.** p2-inc/keycloak-orgs is therefore no longer the only org model, and the two are *independent implementations*:

- p2-inc's own note (`docs/note-keycloak-organizations-feature.md`) says they plan **not** to enable native organizations in their hosted product and ship it **off** in their images, that the extension "is not going away", and that a migration path appears only *if* feature parity arrives.
- Practically: install **both** and the MCP sees **two parallel org namespaces**, native `organizations` in the Admin REST API, and Phase Two's `/realms/{realm}/orgs`. That is a confusing surface to expose to an agent.
- **Recommendation:** use **native Organizations** (zero JARs, stable Admin REST). The p2-inc extension is not shipped by default: its component JAR expects `keycloak-scim-server` classes that are absent from a stock image, and the resulting `NoClassDefFoundError` breaks `/admin/serverinfo` and any tooling that calls it, including Terraform. Add it only together with `keycloak-scim-server` and verify `/admin/serverinfo` afterwards.
- Unverified: whether p2-inc's JAR conflicts at the schema/table level with native org entities. They use separate JPA entities (`OrganizationSpi`), so coexistence is expected to work; **smoke-test before relying on it**.

## 4. Install mechanics and dependency traps

- **Provider JARs** go in `/opt/keycloak/providers/`, then **`kc.sh build`** (augmentation). Start with `--optimized` afterwards. No `--features` flag is needed for any SAFE item, none of them are feature-gated.
- **These p2-inc JARs are *component* JARs, not shaded.** Every Keycloak/3rd-party dep in `keycloak-orgs`' pom is `provided` **except two that must be supplied at runtime**: `dnsjava` (pinned below) and `io.phasetwo.keycloak:keycloak-scim-server` (declared `provided`, i.e. *assumed present in the runtime*, **on a stock 26.8.1 image that assumption is false**). The missing class breaks `/admin/serverinfo` with `NoClassDefFoundError`; the fallback is Phase Two's own image `quay.io/phasetwo/phasetwo-keycloak`, which bundles them.
- `keycloak-events` additionally needs **`com.github.xgp:kitchen-sink`** at runtime (only compile-scope dep; version 0.1 pinned below).
- `keycloak-magic-link` has **no** compile-scope deps, cleanest drop-in of the three.
- **netzbegruenung** ships both shaded (`netzbegruenung.*`) and unshaded (`original-*`) assets. Use the shaded ones; I re-verified all five against the publisher's `.sha512`, **all matched**.
- **SBOM/transitive concerns:** `keycloak-orgs` pulls BouncyCastle (`bcprov-jdk18on`) and a SCIM implementation; `app-authenticator` is a 2.8 MB shaded JAR. Nothing here is vetted by the Keycloak team, the extensions page says so explicitly. Every artifact below is pinned by `sha256` in the Containerfile via `ADD --checksum` (Podman ≥ 4.5).
- **JVM/module notes:** none of these require extra JVM flags; all are plain provider JARs (service-loader entries verified by `unzip -l …/META-INF/services/org.keycloak.*`).

## 5. Sources

- Extensions index (source of the 68 cards, stars, and repo slugs): https://www.keycloak.org/extensions
- Keycloak 26.8.1 release: https://github.com/keycloak/keycloak/releases/tag/26.8.1
- Keycloak config reference (native metrics, DPoP): https://www.keycloak.org/server/all-config
- p2-inc orgs note on native Organizations: https://github.com/p2-inc/keycloak-orgs/blob/main/docs/note-keycloak-organizations-feature.md
- Maven Central: `io.phasetwo.keycloak:{keycloak-orgs,keycloak-magic-link,keycloak-events}` · `dnsjava:dnsjava` · `com.github.xgp:kitchen-sink`
- netzbegruenung release `v26.8.0-1`: https://github.com/netzbegruenung/keycloak-mfa-plugins/releases/tag/v26.8.0-1
- kcwarden: https://pypi.org/project/kcwarden/
