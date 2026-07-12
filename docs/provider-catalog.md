# Provider catalog

The provider catalog supplies reviewed operational context for commonly used
email services. It is not an authorization list, DNS cache, reputation feed,
or source of health points. Live DNS and the organization's normalized sender
inventory remain authoritative.

## Default catalog

`DefaultProviderCatalog` loads a strict, embedded YAML document without network
access. The current catalog includes eighteen providers. The original release
set was supplemented by authentication infrastructure observed repeatedly in a
private mail-header sample; no message bodies, recipient data, or private
sending domains were copied into the catalog.

| Provider | Static SPF names recognized | Other reviewed context |
| --- | --- | --- |
| Adobe Marketo Engage | `mktomail.com` | Tenant-specific DKIM and DKIM-first DMARC alignment guidance |
| Amazon SES | `amazonses.com` | Easy DKIM/BYODKIM and custom MAIL FROM MX/SPF requirements |
| AWeber | None | Three documented DKIM CNAME selectors and separate DMARC setup |
| Campaign Monitor | `_spf.createsend.com` | Tenant-specific DKIM and default return-path alignment limitation |
| Constant Contact | None | Tenant-specific DKIM and documented SPF alignment limitation |
| Google Workspace | `_spf.google.com` | Customer selector TXT setup and 2048-bit recommendation |
| HubSpot Marketing Email | Tenant subdomains beneath `hubspotemail.net` | Two tenant-specific DKIM CNAMEs and aligned sending-domain setup |
| Klaviyo | None | Dynamic NS delegation or static authentication CNAMEs |
| Mailchimp | None | Tenant-specific authentication CNAMEs and separate DMARC setup |
| Mailchimp Transactional | None | `mte1`/`mte2` DKIM CNAMEs, DMARC, verification, and custom return path |
| Mailgun | `mailgun.org` | Tenant-specific DKIM and optional tracking/inbound records |
| Microsoft 365 | `spf.protection.outlook.com`, `spf.protection.office365.us`, `spf.protection.partner.outlook.cn` | Two tenant-specific DKIM CNAME selectors and provider-managed rotation |
| Omnisend | None | Tenant-specific SPF, DKIM, and DMARC records with relaxed alignment guidance |
| Postmark | `spf.mtasv.net` | Tenant-specific DKIM and preferred custom return-path CNAME alignment |
| Salesforce | `_spf.salesforce.com` | Tenant-specific DKIM context; unverified selector details remain unknown |
| Shopify | None | Tenant-specific SPF/DKIM CNAMEs and separate DMARC setup |
| Twilio SendGrid | `sendgrid.net` | Automated SPF/DKIM CNAME management and two rotating selectors |
| Zendesk | `mail.zendesk.com` | Tenant-specific DKIM context; unverified selector details remain unknown |

The catalog deliberately omits `servers.mcsv.net` and `shops.shopify.com` from
static matching. Although they appear in other providers' guidance and older
examples, the current first-party Mailchimp and Shopify setup instructions
reviewed for this catalog describe tenant-specific CNAME records instead. A
catalog entry leaves uncertain fields empty rather than turning secondary or
historical material into an authoritative default.

The reviewed first-party contracts are:

- [Google Workspace SPF](https://knowledge.workspace.google.com/admin/security/set-up-spf)
  and [DKIM](https://knowledge.workspace.google.com/admin/security/set-up-dkim)
- [Microsoft 365 SPF](https://learn.microsoft.com/en-us/defender-office-365/email-authentication-spf-configure)
  and [DKIM](https://learn.microsoft.com/en-us/defender-office-365/email-authentication-dkim-configure)
- [Amazon SES custom MAIL FROM](https://docs.aws.amazon.com/ses/latest/dg/mail-from.html),
  [DKIM](https://docs.aws.amazon.com/ses/latest/dg/send-email-authentication-dkim.html),
  and [DMARC alignment](https://docs.aws.amazon.com/ses/latest/dg/send-email-authentication-dmarc.html)
- [Mailchimp domain authentication](https://mailchimp.com/help/set-up-email-domain-authentication/)
- [Salesforce SPF guidance](https://help.salesforce.com/s/articleView?id=000386321&type=1)
- [Shopify sender email setup](https://help.shopify.com/en/manual/intro-to-shopify/initial-setup/setup-your-email)
- [Zendesk sender authorization](https://support.zendesk.com/hc/en-us/articles/4408832543770-Allowing-Zendesk-to-send-email-on-behalf-of-your-email-domain)
- [Adobe Marketo SPF and DKIM](https://experienceleague.adobe.com/en/docs/marketo/using/getting-started/initial-setup/configure-protocols-for-marketo)
- [Campaign Monitor authentication](https://help.campaignmonitor.com/articles/Knowledge/email-authentication)
  and [SPF include](https://help.campaignmonitor.com/articles/Knowledge/allowlist-campaign-monitors-addresses)
- [Constant Contact authentication](https://knowledgebase.constantcontact.com/email-digital-marketing/tutorials/KnowledgeBase/5865-Understanding-email-authentication?lang=en_US)
- [HubSpot authentication](https://knowledge.hubspot.com/marketing-email/manage-email-authentication-in-hubspot?page=1)
- [Klaviyo branded sending domains](https://help.klaviyo.com/hc/en-us/articles/115000357752)
- [Mailchimp Transactional authentication](https://mailchimp.com/developer/transactional/docs/authentication-delivery/)
- [Mailgun domain verification](https://documentation.mailgun.com/docs/mailgun/user-manual/domains/domains-verify)
- [Postmark SPF and return-path guidance](https://postmarkapp.com/support/article/how-do-i-set-up-spf-for-postmark)
- [Twilio SendGrid domain authentication](https://www.twilio.com/docs/sendgrid/ui/account-and-settings/how-to-set-up-domain-authentication)
- [AWeber DKIM authentication](https://help.aweber.com/hc/en-us/articles/360023682313-How-do-I-set-up-DKIM-authentication-records-for-my-domain)
- [Omnisend sender-domain authentication](https://support.omnisend.com/en/articles/3385292-set-up-your-email-domain-in-omnisend)

## Matching

`MatchSPFInclude` normalizes a supplied DNS name and applies the rule stored in
the catalog. Every embedded rule is `exact`. An attacker-controlled name such
as `_spf.google.com.attacker.example` does not match `_spf.google.com`.

`MatchSPFRelationship` is the safer entry point for a parsed `SPFRelationship`:
it accepts only static `include` and `redirect` relationships and rejects
macro-controlled targets. A caller-owned entry may use a suffix rule only when
it explicitly selects `suffix` and supplies a documentation note. Normalization
rejects overlapping match rules so iteration order cannot change the provider.

Every returned `ProviderMatch` has `context_only: true`. It can explain a DNS
dependency and shared infrastructure, but it does not:

- authorize an expected sender;
- prove the live include resolves or is syntactically healthy;
- grant health or maturity points;
- trust an IP address, ASN, message, or account;
- suppress evidence or penalize an unknown provider.

Health, correlation, and threat-analysis stages must consume this context as a
separate input and retain their own authoritative evidence and result state.

## Strict caller catalogs

`LoadProviderCatalogYAML` accepts one document up to 1 MiB. It rejects unknown
fields, aliases, environment placeholders, secret-bearing keys, unsupported
schema versions, invalid IDs or DNS names, bad review dates, non-HTTPS or
non-first-party documentation, duplicate IDs or aliases, broken successor
links, successor cycles, and overlapping SPF rules. Normalized catalogs contain
at most 256 providers and bound per-entry strings and collections.

Catalog data is inert. The library does not fetch documentation, expand SPF,
download updates, interpret templates, or accept provider IP ranges. Catalog
notes and titles remain data; applications must not turn them into executable
instructions.

## Private providers and overlays

Internal relays, acquired-company services, and contract-specific providers can
be loaded as caller catalogs or added with `OverlayProviderCatalog`. An overlay
does not mutate the base or any package-global state. New IDs are add-only.
Replacing an existing provider requires the exact ID in
`ReplaceProviderIDs`; unused or silent replacements fail.

`ProviderCatalog.Provenance` records the effective digest, base and overlay
digests, overlay version, and sorted added/replaced IDs. Persist this provenance
with downstream results so a provider explanation can be traced to the exact
catalogs used.

Keep private additions in their own file rather than editing
`providers/default.yaml`:

```yaml
schema_version: 1
catalog_version: "2026-07-12"
providers:
  - id: internal-relay
    name: Internal Relay
    status: active
    official_domains: [example.test]
    spf:
      includes:
        - name: spf.relay.example.test
          status: active
          match: exact
          evidence_confidence: high
      live_expansion_required: true
    dkim:
      setup_model: Organization-managed selector TXT records
      custom_domain_signing_expected: true
      tenant_specific: true
      provider_managed_rotation: false
    alignment:
      custom_mail_from: unknown
      custom_mail_from_required_for_spf_dmarc_alignment: false
    infrastructure:
      shared: false
    documentation:
      - url: https://docs.example.test/mail/relay
        title: Internal relay authentication contract
    reviewed_at: "2026-07-12"
    evidence_confidence: high
```

The application owns filesystem access and passes the bytes explicitly:

```go
data, err := os.ReadFile("private-providers.yaml")
if err != nil {
	return err
}
privateCatalog, err := dmarcgo.LoadProviderCatalogYAML(data)
if err != nil {
	return err
}
base, err := dmarcgo.DefaultProviderCatalog()
if err != nil {
	return err
}
effective, err := dmarcgo.OverlayProviderCatalog(base, dmarcgo.ProviderCatalogOverlay{
	Catalog: privateCatalog,
})
if err != nil {
	return err
}
_ = effective
```

The same `privateCatalog` can be used by itself instead. The library
deliberately does not read an additional file path implicitly.

Private catalogs must contain provider-owned or organization-owned documentation
domains, never secrets, tenant IDs, customer domains that are not explicitly in
scope, static provider IP ranges, or executable DNS templates. Do not commit
private operational catalogs to this repository.

## Maintenance

Embedded changes are security-sensitive data changes. Review every changed
field against current first-party documentation and update `reviewed_at` only
after that review. `ValidateProviderCatalogReviewDates` is a pure check that
lets applications and CI select an explicit as-of time and maximum age. Live
DNS changes do not require a catalog release; consumers resolve and parse DNS
in the explicit collection stages.
