# Changelog

## [Unreleased]

### Added

- Add task-local evidence-bound session hypotheses and offline identification metrics (#57/#58); always abstain from uncalibrated actor identity, with no runtime hook or product pin change.

- Add a standalone offline MIO IR utility for local case creation, bounded
  evidence import and verification, timelines, and JSON/Markdown reports.
- Add a separate Fabric Knowledge Context v1 advisory input, preserving facts,
  inferences, unknowns and limitations without treating provider claims as verified.

### Fixed

- Do not report a partial or stale Fabric Knowledge Context snapshot as an available Knowledge dependency; retain it only as an unverified advisory and add a fixed follow-up check.
- Fabric advisory projection: reject private, shorthand, integer, hex and zone-scoped IP forms in typed address subjects and URL hosts, including nested or joined URLs in copied strings; refuse IPv4-compatible, IPv4-translated, NAT64, 6to4 and Teredo IPv6 prefixes deterministically; and apply strict authority and normalized type checks.
- Reject the entire Knowledge context advisory when defensive-state canonicalization metadata contradicts itself; keep legacy reports without canonical metadata unverified.
- Sanitize terminal and bidirectional control characters in untrusted Markdown
  summaries, and prevent case-aliased report paths from targeting storage.
- Reject future-dated Fabric Knowledge Context responses and omit Knowledge advisories from coordinated non-current results.

## Session software pilot (2026-11-10)

- Freeze 24 synthetic replay cases, disjoint replay partitions, digest-bound acceptance and an offline pilot report. Actor truth remains unknown; no calibration, training, core registration, pin or admission change.
