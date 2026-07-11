## Summary

Describe the consumer problem and the implemented solution.

## Change type

- [ ] Bug fix
- [ ] Additive feature
- [ ] Breaking API change
- [ ] Documentation or tooling
- [ ] Dependency update

## Public API and behavior

- [ ] Exported API changes are intentional and documented.
- [ ] Error wrapping remains compatible with `errors.Is` and `errors.As` where applicable.
- [ ] Input limits, cancellation, resource cleanup, and untrusted-data behavior were considered.
- [ ] The change keeps mailbox ingestion, storage, scheduling, dashboards, DNS, and RFC 9991 parsing outside library scope.

## Validation

- [ ] `make ci` passes.
- [ ] New or changed public behavior has tests.
- [ ] README examples compile when documentation changed.
- [ ] `CHANGELOG.md` is updated for user-facing changes.

## Fixture privacy

- [ ] No live DMARC reports or private corpus files are included.
- [ ] Derived fixtures are synthetic or anonymized, including extension XML review.
