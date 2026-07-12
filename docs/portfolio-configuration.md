# Organization portfolio configuration

The portfolio model describes what an organization owns and intends to monitor.
It stores DNS record names and expected-sender policy, not live DNS record
values. Loading and normalization never perform DNS lookups, report processing,
or enrichment.

## APIs

- Construct `PortfolioConfig` and call `NormalizePortfolio` for programmatic
  configuration.
- Call `ParsePortfolioYAML` when the caller needs the strict transport value.
- Call `LoadPortfolioYAML` to decode and normalize in one step.
- Call `ValidatePortfolio` for stable, value-safe diagnostics without I/O.
- Use the accessors on `Portfolio` to obtain normalized defensive copies.

`PortfolioSchemaVersion` is currently `1`. Portfolio schema versions,
`AnalysisContractVersion`, output schema versions, and Go module versions are
independent contracts.

## Minimal configuration

```yaml
schema_version: 1
organization:
  id: example-org
entities:
  - id: corporate
    domains:
      - name: example.test
        include_subdomains: true
        records:
          spf: [example.test]
          dmarc: [_dmarc.example.test]
          dkim: [primary._domainkey.example.test]
        expected_senders: [workspace]
expected_senders:
  - id: workspace
    name: Workspace
    require_either: true
    allowed_selectors: [primary]
```

The complete DKIM record name is required. Selectors cannot be enumerated
reliably from DNS.

## Organization and ownership

`organization` identifies the complete portfolio. `entities` represent
business units, subsidiaries, acquisitions, or sister organizations. An entity
may name another entity as its `parent`; it inherits the parent owner and tags,
then applies its own owner override and merged tags. Domains are not inherited
between entities.

Reusable `owners` provide stable accountability IDs plus optional display name,
contact, and tags. Organization, entity, domain, sender, and exclusion owner
fields reference those IDs. Diagnostics contain paths and library-generated
messages but never copy contact data or rejected configuration values.

## Sender requirements and reusable policies

An expected sender can reference a reusable policy:

```yaml
policies:
  - id: either-aligned
    require_either: true
    allowed_selectors: [primary, secondary]
expected_senders:
  - id: shared-workspace
    owner: mail-team
    policy: either-aligned
```

Or it can define an inline requirement:

```yaml
expected_senders:
  - id: transactional-mail
    require_spf: true
```

`require_either` is mutually exclusive with `require_dkim` and `require_spf`.
Setting both `require_dkim` and `require_spf` means both mechanisms are required.
A sender cannot combine a reusable policy reference with inline requirements.
Provider metadata identifies a documented provider but does not authorize it;
domains explicitly authorize senders through `expected_senders`.

## Domain inheritance

A domain inherits only when it explicitly names a parent domain in the same
entity. The parent must be a DNS ancestor of the child.

- Owner and policy are scalar values: the child inherits them when empty and
  overrides them when set.
- Tags, record names, expected senders, and exclusions default to `merge`.
- Each collection may use `replace` under `inheritance`.
- Merged values are normalized, deduplicated, and sorted.
- A child exclusion with the same ID replaces the inherited exclusion.
- `include_subdomains` applies only to the domain on which it is declared.

```yaml
domains:
  - name: example.test
    owner: mail-team
    policy: either-aligned
    records:
      spf: [example.test]
    expected_senders: [workspace]
  - name: marketing.example.test
    parent: example.test
    policy: dkim-required
    records:
      spf: [marketing.example.test]
    inheritance:
      expected_senders: replace
    expected_senders: [campaign-platform]
```

If a child changes ownership while inheriting record names, the resulting
shared record names must not conflict with another effective owner. Use
`inheritance.records: replace` when the child owns an independent record set.

## Scoped exclusions

Every exclusion requires an ID, accountable owner, reason, scope, and creation
time. Expiration is optional but must be later than creation.

- `domain` and `subdomains` scopes do not accept a target.
- `record` requires a complete DNS record-name target.
- `sender` requires an expected-sender ID target.

Exclusions express caller-owned operational context. They do not suppress
authentication evidence globally and do not authorize automatic action.

## Strict YAML and environment expansion

The YAML loader:

- accepts exactly one document;
- requires schema version 1;
- rejects unknown fields and YAML aliases;
- rejects secret-bearing keys such as passwords, tokens, credentials, API keys,
  and private keys;
- limits input to 4 MiB;
- does not read process environment variables.

Environment expansion is opt-in and supports `${NAME}` string placeholders:

```go
portfolio, err := dmarcgo.LoadPortfolioYAML(data,
    dmarcgo.WithPortfolioEnvironment(os.LookupEnv),
)
```

Passing `os.LookupEnv` is an explicit application decision. Tests should pass a
map-backed lookup instead. Missing variables fail without copying their values
into errors. Quote placeholders inside YAML flow collections.

## Normalization and validation

- IDs, references, selectors, tags, and DNS names normalize to lowercase.
- Internationalized domains normalize to A-label form.
- Trailing DNS dots are removed.
- Public suffixes, IP literals, malformed labels, invalid DKIM/DMARC names,
  duplicate IDs, duplicate exact record names, broken references, cycles,
  contradictory policies, and ownership conflicts are rejected.
- All normalized collections have deterministic ordering.
- `Portfolio.Digest` is stable across semantically equivalent input ordering.
- Accessors return deep copies so callers cannot mutate the normalized value.

`PortfolioValidationError` supports `errors.Is(err, ErrInvalidPortfolio)` and
`errors.As` for retrieving structured diagnostics. YAML, environment, size, and
schema errors have separate sentinel errors.

The synthetic multi-entity example used by tests is available at
`testdata/portfolio/large-synthetic.yaml`.
