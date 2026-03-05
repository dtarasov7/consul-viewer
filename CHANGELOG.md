# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, adapted for this repository.

## [1.1.0] - 2026-03-05

### Changed

- Added compatibility updates for deployment environments with Python `3.8.x` and `urwid 2.0.1`.
- Reworked `LineBox` title styling to avoid using unsupported `urwid` constructor arguments in older releases.
- Updated runtime requirements in README files to Python `3.8+` and `urwid>=2.0.1,<3.0`.
- Fixed ACL policy rules rendering for tab-indented text by normalizing tabs for terminal display.
- Services list view now shows `Name / Inst / Status`; the `Tags` column was removed and width was shifted to `Name`.
- Refined `F7` filtering behavior:
  - Services list: filter only by service name.
  - Instance lists: dedicated dialog with `Instance`, `Service`, `Address`, and `AND/OR` match mode.
- Added bulk selection for services and nodes in list mode:
  - `Space` toggles row selection.
  - `F12` applies selection by regex mask.
  - `Enter` opens a merged instances view for all selected services/nodes.

## [1.0.0] - 2026-03-04

### Added

- Initial public release of `Consul Viewer TUI`
- Read-only terminal UI for Consul built with `urwid`
- Dashboard with cluster and local agent summary
- Telemetry section based on Prometheus-formatted agent metrics
- Services and service instances views
- Nodes and node instances views
- KV browser with preview and full viewer
- Sessions list and details
- ACL read-only sections for tokens, policies, roles, and auth methods
- Text filtering, status filtering, structured instance filtering, and per-view sorting
- Background loading, TTL cache, stale-state handling, and popup-based diagnostics
- User guides, README files, and PlantUML architecture diagrams
