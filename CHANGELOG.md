# Changelog

## [Unreleased]

### Added

- Add a separate Fabric Knowledge Context v1 advisory input, preserving facts,
  inferences, unknowns and limitations without treating provider claims as verified.

### Fixed

- Reject private, shorthand, integer and hex IP forms in typed address subjects and URL hosts, including URLs embedded in other copied advisory strings; screen IPv6 transition prefixes against embedded non-global IPv4.
- Reject the entire Knowledge context advisory when defensive-state canonicalization metadata contradicts itself; keep legacy reports without canonical metadata unverified.
- Reject future-dated Fabric Knowledge Context responses and omit Knowledge advisories from coordinated non-current results.
