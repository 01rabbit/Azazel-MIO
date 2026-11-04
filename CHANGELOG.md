# Changelog

## [Unreleased]

### Added

- Add a separate Fabric Knowledge Context v1 advisory input, preserving facts,
  inferences, unknowns and limitations without treating provider claims as verified.

### Fixed

- Reject the entire Knowledge context advisory when defensive-state canonicalization metadata contradicts itself; keep legacy reports without canonical metadata unverified.
- Reject future-dated Fabric Knowledge Context responses and omit Knowledge advisories from coordinated non-current results.
