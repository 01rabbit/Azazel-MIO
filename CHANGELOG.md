# Changelog

## [Unreleased]

### Added

- Add a separate Fabric Knowledge Context v1 advisory input, preserving facts,
  inferences, unknowns and limitations without treating provider claims as verified.

### Fixed

- Fabric advisory projection: reject private, shorthand, integer, hex and zone-scoped IP forms in typed address subjects and URL hosts, including nested or joined URLs in copied strings; refuse IPv4-compatible, IPv4-translated, NAT64, 6to4 and Teredo IPv6 prefixes deterministically; and apply strict authority and normalized type checks.
- Reject the entire Knowledge context advisory when defensive-state canonicalization metadata contradicts itself; keep legacy reports without canonical metadata unverified.
- Reject future-dated Fabric Knowledge Context responses and omit Knowledge advisories from coordinated non-current results.
