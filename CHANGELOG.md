# Changelog

## [Unreleased]

### Added

- Add a standalone offline MIO IR utility for local case creation, bounded
  evidence import and verification, timelines, and JSON/Markdown reports.

### Fixed

- Reject the entire Knowledge context advisory when defensive-state canonicalization metadata contradicts itself; keep legacy reports without canonical metadata unverified.
- Sanitize terminal and bidirectional control characters in untrusted Markdown
  summaries, and prevent case-aliased report paths from targeting storage.
