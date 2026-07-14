# Security Policy

## Supported versions

Security fixes are applied to the current major release line.

| Version | Supported |
| --- | --- |
| 2.x | Yes |
| 1.x | No |

## Reporting a vulnerability

Please report security issues privately rather than opening a public issue. Use GitHub's private vulnerability reporting if it is enabled for the repository, or contact the maintainer directly.

## Input handling expectations

DMARC aggregate reports are external input and should be treated as untrusted. This project limits decompressed payload reads by default and avoids network access while parsing, but callers remain responsible for controlling where report files come from and how parsed data is stored or displayed.

Do not feed DMARC failure reports, mailbox exports, or arbitrary email messages into this parser. RFC 9991 failure reports can contain message headers, body content, and personally identifiable information, and are intentionally out of scope for this package.

## Security-simulation campaign data

Campaign inventories and privileged classification output can reveal exercise
timing, target scope, identities, infrastructure, delivery exceptions, approval
references, and restricted workflow details. Store and transmit them only
inside the authorized campaign/SOC boundary. Use the disclosure-safe output
view for ordinary reporting workflows; it deliberately omits exact campaign
state and identifiers.

Do not put credentials, message bodies, raw campaign tokens, or secrets in a
campaign configuration, source error, log, fixture, or output. The configuration
contract rejects common secret-bearing fields and accepts only complete SHA-256
token/content digests, but callers remain responsible for securing source
transports, storage, logs, and retained snapshots.

Campaign correlation is not an allowlist. A provider, sender domain, URL,
delivery exception, hostname, or source IP alone never establishes authorized
simulation status. Missing, invalid, future, stale, expired, or unavailable
required authorization must leave ordinary suspicious-message handling intact.
Preserve authentication failures and other threat evidence even after a
high-confidence match.

Source resolution is explicit. The library does not discover configuration,
read process environment variables, follow directory symlinks, refresh remote
feeds, retry, or use credentials implicitly. The HTTPS adapter blocks downgrade
redirects before sending them. Applications own same-scheme redirect, TLS,
proxy, credential, cache, rate, retention, and last-known-good policy.
Directory discovery rejects symlink roots and entries and binds returned file
sources to the discovered root identity.

Treat campaign/provider names, tickets, source metadata, message fields,
provenance, and workflow IDs as untrusted data. Keep them in structured fields;
never concatenate them into prompts, employee messages, headlines,
recommendations, actions, or instructions.
