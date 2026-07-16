# Owner-authorized report samples

The `georgestarcher.com` directory contains three real DMARC aggregate reports
included with the domain owner's explicit permission. They form a small
point-in-time newcomer corpus with three reporting organizations, two passing
observations, and one rejected observation where SPF and DKIM both failed.

The samples are operational evidence, not synthetic fixtures and not a
continuing claim about the domain or any observed source. They are used only by
the documentation exercise; deterministic package tests continue to use the
synthetic fixtures under `testdata`.

DMARC aggregate reports contain source IPs, authentication identities, report
periods, receiver contacts, and policy details. Review and obtain authorization
before publishing reports for another domain. Do not add more private reports
merely because this narrowly scoped owner-authorized example exists.
