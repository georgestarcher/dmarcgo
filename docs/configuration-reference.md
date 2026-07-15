# Configuration reference

`dmarcgo` accepts two organization-owned configuration families: organization
portfolios and security-simulation campaign inventories. Provider catalogs and
offline intelligence snapshots are separate caller-owned inputs with their own
focused guides.

YAML and JSON use the same field names. Decoders are strict: unknown fields,
multiple YAML documents, aliases, unsupported schema versions, oversized
documents, and secret-bearing field names fail validation. Store references and
public evidence in these files, never credentials or private keys.

## Portfolio configuration

Use `LoadPortfolioYAML` for strict YAML or `NormalizePortfolio` for a Go
`PortfolioConfig`. Loading and normalization perform no DNS, report, filesystem,
environment, or network access except reading bytes the application already
supplied. Environment expansion occurs only when the caller passes
`WithPortfolioEnvironment`.

### Top-level fields

| Field | Type | Required | Default and meaning | Sensitivity and validation |
| --- | --- | --- | --- | --- |
| `schema_version` | integer | Yes | Must be `1` | Unsupported versions fail |
| `organization` | object | Yes | Portfolio owner and identity | Internal IDs and ownership may be operational |
| `owners` | array of owner objects | No | Empty | Contacts may be restricted; diagnostics never copy them |
| `policies` | array of policy objects | No | Empty | IDs must be unique |
| `expected_senders` | array of sender objects | No | Empty | A declaration is organization intent, not proof of live authorization |
| `entities` | array of entity objects | Yes | No implicit entity | IDs and parent references must be valid |

### Organization, owner, policy, and sender fields

| Object and field | Type | Required | Default and allowed values |
| --- | --- | --- | --- |
| `organization.id` | string | Yes | Stable organization ID |
| `organization.name` | string | No | Empty display name |
| `organization.owner` | string | No | Empty or an owner ID |
| `organization.tags` | string array | No | Empty, normalized and sorted |
| `owners[].id` | string | Yes | Stable unique owner ID |
| `owners[].name` | string | No | Empty display name |
| `owners[].contact` | string | No | Empty internal route; never interpolated into diagnostics |
| `owners[].tags` | string array | No | Empty |
| `policies[].id` | string | Yes | Stable unique policy ID |
| `policies[].require_dkim` | boolean | No | `false` |
| `policies[].require_spf` | boolean | No | `false` |
| `policies[].require_either` | boolean | No | `false`; cannot contradict the other requirements |
| `policies[].allowed_selectors` | string array | No | Empty exact selector values |
| `expected_senders[].id` | string | Yes | Stable unique sender ID |
| `expected_senders[].name` | string | No | Empty display name |
| `expected_senders[].provider` | string | No | Empty provider-catalog ID; recognition remains context only |
| `expected_senders[].owner` | string | No | Empty or an owner ID |
| `expected_senders[].tags` | string array | No | Empty |
| `expected_senders[].policy` | string | No | Empty or a reusable policy ID |
| `expected_senders[].require_dkim` | boolean | No | Inline policy; `false` |
| `expected_senders[].require_spf` | boolean | No | Inline policy; `false` |
| `expected_senders[].require_either` | boolean | No | Inline policy; `false` |
| `expected_senders[].allowed_selectors` | string array | No | Inline exact selectors; empty |

Do not combine a reusable `policy` reference with contradictory inline
requirements. A provider ID explains documented setup; domains must still
reference the expected-sender ID explicitly.

### Entity and domain fields

| Object and field | Type | Required | Default and allowed values |
| --- | --- | --- | --- |
| `entities[].id` | string | Yes | Stable unique entity ID |
| `entities[].name` | string | No | Empty display name |
| `entities[].parent` | string | No | Empty or an entity ID; cycles fail |
| `entities[].owner` | string | No | Inherited when empty |
| `entities[].membership` | string | No | `owned`; allowed `owned`, `reference` |
| `entities[].tags` | string array | No | Merged with inherited organization/entity tags |
| `entities[].domains` | domain array | No | Empty |
| `domains[].name` | string | Yes | Canonical domain; normalized to an IDNA A-label |
| `domains[].parent` | string | No | Empty or an explicit domain in the same entity |
| `domains[].include_subdomains` | boolean | No | `false`; describes declared scope, not DNS discovery |
| `domains[].owner` | string | No | Inherited when empty |
| `domains[].tags` | string array | No | Inherited using the selected collection mode |
| `domains[].policy` | string | No | Inherited when empty or references a policy ID |
| `domains[].records` | object | No | Empty declared record-name collections |
| `domains[].expected_senders` | string array | No | Sender IDs; inherited using the selected collection mode |
| `domains[].exclusions` | exclusion array | No | Caller-owned scoped exceptions |
| `domains[].inheritance` | object | No | Every collection defaults to `merge` |

### Record, inheritance, and exclusion fields

| Object and field | Type | Required | Default and allowed values |
| --- | --- | --- | --- |
| `records.spf` | string array | No | Complete SPF TXT owner names, not record values |
| `records.dkim` | string array | No | Complete selector `_domainkey` owner names |
| `records.dmarc` | string array | No | Complete `_dmarc` owner names |
| `inheritance.tags` | string | No | `merge`; allowed `merge`, `replace` |
| `inheritance.records` | string | No | `merge`; allowed `merge`, `replace` |
| `inheritance.expected_senders` | string | No | `merge`; allowed `merge`, `replace` |
| `inheritance.exclusions` | string | No | `merge`; allowed `merge`, `replace` |
| `exclusions[].id` | string | Yes | Stable unique exception ID |
| `exclusions[].owner` | string | Yes | Accountable owner ID |
| `exclusions[].reason` | string | Yes | Caller-controlled reason, retained as data |
| `exclusions[].scope` | string | Yes | `domain`, `subdomains`, `record`, `sender`, or `source` |
| `exclusions[].target` | string | Sometimes | Required when the selected scope needs a specific target |
| `exclusions[].created_at` | RFC 3339 time | Yes | Explicit creation time |
| `exclusions[].expires_at` | RFC 3339 time | No | No expiration; expired exclusions remain visible but inactive |

The normalized portfolio owns defensive copies, canonicalizes and sorts values,
and produces a deterministic digest. See
[portfolio configuration](portfolio-configuration.md) for inheritance,
environment expansion, validation, and scope examples.

## Campaign configuration

Use `LoadCampaignConfiguration` for strict YAML or JSON and
`NormalizeCampaignConfiguration` for `CampaignConfigurationConfig`. Use
`ResolveCampaignConfiguration` only when the application deliberately supplies
one or more source adapters. Imports reference supplied source IDs; the library
never discovers or fetches an unlisted import.

The machine-readable schema is
[`schemas/campaign/configuration/v1.json`](../schemas/campaign/configuration/v1.json)
and is available through `CampaignConfigurationSchema`.

### Document and import fields

| Field | Type | Required | Default and meaning |
| --- | --- | --- | --- |
| `schema_version` | integer | Yes | Must be `1` |
| `generated_at` | RFC 3339 time | Yes | Source generation time |
| `effective_at` | RFC 3339 time | No | Defaults to `generated_at` |
| `expires_at` | RFC 3339 time | Yes | Must be after generation and effective time |
| `imports` | array | No | Empty; references only explicit source IDs |
| `imports[].source_id` | string | Yes | Stable supplied source ID |
| `imports[].required` | boolean | No | `false`; required failures make authorization unavailable |
| `security_simulations` | array | Yes | Use `[]` for an authoritative empty inventory; omitted or null is invalid |

### Campaign identity and lifecycle fields

| Field | Type | Required | Default and allowed values |
| --- | --- | --- | --- |
| `security_simulations[].id` | string | Yes | Stable campaign ID |
| `external_campaign_id` | string | No | Empty external reference |
| `provider.type` | string | Yes | `catalog` or `self_hosted` |
| `provider.id` | string | Yes | Stable provider/platform ID |
| `provider.name` | string | No | Display name; required by validation where self-hosted identity needs it |
| `organization` | string | Yes | Exact organization scope ID |
| `entity` | string | No | Empty exact entity scope |
| `business_unit` | string | No | Empty exact business-unit scope |
| `owner` | string | Yes | Accountable restricted-data owner |
| `approval_reference` | string | Yes | Caller-controlled approval reference |
| `status` | string | Yes | `scheduled`, `active`, `completed`, or `canceled` |
| `created_at` | RFC 3339 time | Yes | Campaign creation time |
| `valid_from` | RFC 3339 time | Yes | Inclusive authorization-window start |
| `valid_until` | RFC 3339 time | Yes | Authorization-window end |
| `recipient_domains` | string array | No | Exact normalized recipient domains |
| `recipient_scope_ids` | string array | No | Exact caller-owned scope IDs |
| `expected_identity` | object | Yes | Exact message identity candidates; no single domain is sufficient authorization |
| `expected_sources` | object | No | Empty optional infrastructure evidence |

Canceled campaigns retain audit context but never authorize a classification.
Completed campaigns may match evidence only from their original valid window.

### Expected identity, sources, and signals

| Field | Type | Required | Default and meaning |
| --- | --- | --- | --- |
| `expected_identity.header_from_domains` | string array | No | Exact author domains |
| `expected_identity.envelope_from_domains` | string array | No | Exact MAIL FROM domains |
| `expected_identity.dkim` | object array | No | Exact signing domains and selectors |
| `expected_identity.dkim[].domain` | string | Yes in item | Exact signing domain |
| `expected_identity.dkim[].selectors` | string array | Yes in item | Exact selector values, including digit-leading rotations |
| `expected_identity.message_id_domains` | string array | No | Exact Message-ID domains |
| `expected_sources.cidrs` | string array | No | Explicit canonical networks; never sufficient alone |
| `expected_sources.hostnames` | string array | No | Exact caller-verified hostnames; no PTR lookup is implied |
| `expected_sources.infrastructure_ids` | string array | No | Exact platform/gateway identifiers |
| `campaign_token_digests` | string array | No | Complete lowercase `sha256:` digests only |
| `url_domains` | string array | No | Exact domains; never sufficient alone |
| `content_fingerprints` | string array | No | Complete lowercase `sha256:` digests only |
| `delivery_exception_ids` | string array | No | Exact caller-owned gateway exception IDs |

The normalized reported-message input accepts digests rather than raw body or
campaign tokens. Identity, time, organization scope, a campaign-specific signal,
and appropriate provenance are non-bypassable high-confidence requirements.

### Authentication, response, handling, and match policy

| Field | Type | Required | Default and allowed values |
| --- | --- | --- | --- |
| `authentication.dmarc` | string | No | `optional`; `required`, `optional`, or `not_expected` |
| `authentication.spf` | string | No | `optional`; same values |
| `authentication.dkim` | string | No | `optional`; same values |
| `response_policy` | object | No | Safe disclosure and full analyst defaults |
| `response_policy.employee_disclosure` | string | No | `prohibited`; allowed `prohibited`, `permitted` |
| `response_policy.employee_template_id` | string | No | Empty; disclosure-safe output uses the fixed neutral template contract |
| `response_policy.analyst_visibility` | string | No | `full`; allowed `full`, `redacted` |
| `response_policy.campaign_owner_visibility` | string | No | `full`; allowed `full`, `redacted` |
| `handling` | object | No | Authentication findings retained; automatic disposition disabled |
| `handling.workflow_id` | string | No | Empty restricted route ID |
| `handling.retain_authentication_findings` | boolean | No | `true`; `false` is rejected |
| `handling.automatic_disposition_eligible` | boolean | No | `false`; document-side half of dual opt-in |
| `match_policy` | object | No | Safe identity- and signal-derived defaults |
| `match_policy.required_factors` | string array | No | Safe defaults derived from configured identities/signals |
| `match_policy.minimum_matched_factors` | integer | No | Derived bounded minimum; cannot bypass a required factor |

Allowed factor values are `campaign_window`, `organization_scope`,
`recipient_scope`, `header_from_domain`, `envelope_from_domain`,
`dkim_identity`, `source_address`, `source_hostname`, `message_id_domain`,
`infrastructure_id`, `campaign_token_digest`, `url_domain`,
`content_fingerprint`, `authentication`, `delivery_exception`, and
`evidence_confidence`.

See [campaign correlation](campaign-correlation.md) for source precedence,
last-known-good behavior, provenance confidence, aggregate limitations, and the
privileged/disclosure-safe result boundary.

## Provider catalog configuration

`LoadProviderCatalogYAML` accepts a strict caller-owned provider catalog. The
catalog is context only and contains no credentials, tenant IDs, provider IP
ranges, or executable DNS templates.

| Object and field | Type | Required | Default and allowed values |
| --- | --- | --- | --- |
| `schema_version` | integer | Yes | Must be `1` |
| `catalog_version` | string | Yes | Caller version identifier |
| `providers` | array | Yes | Bounded provider entries |
| `providers[].id` | string | Yes | Stable unique provider ID |
| `providers[].name` | string | Yes | Display name, retained as untrusted data |
| `providers[].aliases` | string array | No | Empty unique aliases |
| `providers[].status` | string | Yes | `active` or `deprecated` |
| `providers[].successor` | string | For deprecated replacement | Empty or another provider ID; cycles fail |
| `providers[].official_domains` | string array | Yes | Reviewed provider-owned domains |
| `providers[].spf` | object | No | Empty static SPF context |
| `providers[].spf.includes` | array | No | Empty documented include/redirect targets |
| `providers[].spf.includes[].name` | string | Yes in item | Canonical static DNS name |
| `providers[].spf.includes[].status` | string | Yes in item | `active` or `deprecated` |
| `providers[].spf.includes[].match` | string | Yes in item | `exact` or explicitly documented `suffix` |
| `providers[].spf.includes[].region` | string | No | Empty display region |
| `providers[].spf.includes[].expected_terminal_behavior` | string | No | Empty, `softfail`, `hardfail`, or `neutral` |
| `providers[].spf.includes[].evidence_confidence` | string | Yes in item | `high`, `medium`, or `low` |
| `providers[].spf.includes[].note` | string | No | Empty untrusted note |
| `providers[].spf.live_expansion_required` | boolean | No | `false`; never triggers expansion |
| `providers[].dkim.setup_model` | string | No | Empty untrusted setup description |
| `providers[].dkim.custom_domain_signing_expected` | boolean | No | `false` |
| `providers[].dkim.selector_patterns` | string array | No | Empty context patterns, not organization selectors |
| `providers[].dkim.preferred_rsa_bits` | integer | No | `0` for unspecified; documented preference only |
| `providers[].dkim.tenant_specific` | boolean | No | `false` |
| `providers[].dkim.provider_managed_rotation` | boolean | No | `false` |
| `providers[].dkim.note` | string | No | Empty untrusted note |
| `providers[].alignment` | object | Yes | Explicit custom MAIL FROM capability context |
| `providers[].alignment.custom_mail_from` | string | Yes | `unknown`, `supported`, or `not_supported` |
| `providers[].alignment.custom_mail_from_required_for_spf_dmarc_alignment` | boolean | No | `false` |
| `providers[].alignment.note` | string | No | Empty untrusted note |
| `providers[].infrastructure` | object | Yes | Explicit shared-infrastructure context |
| `providers[].infrastructure.shared` | boolean | Yes | Shared infrastructure is attribution counter-evidence, not proof of safety |
| `providers[].companion_records` | array | No | Empty non-secret onboarding requirements |
| `providers[].companion_records[].id` | string | Yes in item | Stable record requirement ID |
| `providers[].companion_records[].type` | string | Yes in item | `TXT`, `CNAME`, `MX`, or `NS` |
| `providers[].companion_records[].condition` | string | Yes in item | Untrusted condition text |
| `providers[].companion_records[].purpose` | string | Yes in item | Untrusted purpose text |
| `providers[].documentation` | array | Yes | Reviewed first-party references |
| `providers[].documentation[].url` | HTTPS URL | Yes in item | Provider/organization-owned first-party source |
| `providers[].documentation[].title` | string | Yes in item | Untrusted title |
| `providers[].reviewed_at` | ISO date | Yes | Explicit evidence review date |
| `providers[].contract_note` | string | No | Empty untrusted contract note |
| `providers[].evidence_confidence` | string | Yes | `high`, `medium`, or `low` |

See [provider catalog](provider-catalog.md) for matching, overlap rejection,
review dates, private overlays, and replacement provenance.

## Other configuration families

| Input | Contract and reference |
| --- | --- |
| Provider catalog or private overlay | [Provider catalog guide](provider-catalog.md); strict `LoadProviderCatalogYAML` and explicit `OverlayProviderCatalog` replacement allowlist |
| Phishing-intelligence snapshot | [Phishing intelligence guide](phishing-intelligence.md); caller-owned offline normalized input |
| Jurisdiction policy | [Jurisdiction context guide](jurisdiction-context.md); explicit immutable policy, built-in snapshot versioned by release |
| DNS collection behavior | `DNSCollectionOptions` and [DNS snapshots](dns-snapshots.md); application supplies resolver, clock, bounds, and retry policy |
| Output profiles and bounds | `OutputOptions`, `AnalysisOutputOptions`, and [output contract](output-contract.md) |
| Threat scoring and exclusions | Versioned profile/options in [threat candidates](threat-candidates.md) |
| Export target capability | Builder-specific exact contract in the STIX, ThreatConnect, MISP, or ThreatStream guide |

These inputs are not merged into the portfolio. Keep organization intent,
current DNS evidence, historical receiver evidence, provider context, campaign
authorization, optional intelligence, and destination capabilities separately
versioned and attributable.

## Synthetic configuration files

- [`minimal-synthetic.yaml`](../testdata/portfolio/minimal-synthetic.yaml) is a
  minimal single-domain hosted-mail portfolio.
- [`adoption-synthetic.yaml`](../testdata/portfolio/adoption-synthetic.yaml)
  covers multiple owned entities, an acquisition, a reference entity, hosted,
  marketing, and self-hosted senders, inheritance, and a scoped exception.
- [`large-synthetic.yaml`](../testdata/portfolio/large-synthetic.yaml) is the
  larger deterministic health and workflow fixture used by feature tests.
- [`security-simulations.yaml`](../testdata/fixtures/campaigns/security-simulations.yaml)
  covers a catalog-backed commercial campaign and a self-hosted campaign.

All public samples use reserved domains and documentation address space. Tests
load them through the public strict APIs, and `make docs-check` validates links,
privacy markers, spelling regressions, runnable examples, and sample safety.
