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
