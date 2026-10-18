# ARGUS.EXE — Roadmap

**Vendor:** Sentinel Safeguard LLC
**Tagline:** Security For Everyone.
**Platform:** Windows (.exe)

## Phase 1 — Detection engine
- [ ] File walker (recursive, symlink-safe, permission-error tolerant)
- [ ] SHA-256 hashing pipeline (streamed, no whole-file loads)
- [ ] Signature database format (JSON/SQLite) + loader + integrity check
- [ ] Pattern rules (YARA-style) evaluation
- [ ] CLI: `argus scan <path>` with plain-language results

## Phase 2 — Heuristics
- [ ] Entropy analysis (packed/encrypted payload detection)
- [ ] PE header/import inspection
- [ ] Suspicious behavior rules (persistence, injection, masquerading)
- [ ] Risk scoring model (clean / suspicious / malicious)

## Phase 3 — Real-time watch
- [ ] Filesystem watcher (on-write scanning)
- [ ] Process monitor (on-execute scanning, pre-execution block)
- [ ] Download/execute interception points

## Phase 4 — Quarantine & reporting
- [ ] Encrypted quarantine vault
- [ ] Restore / remove flows (never silent delete)
- [ ] Detection explanations in plain language
- [ ] Scan history + audit log

## Phase 5 — Product
- [ ] GUI
- [ ] Signature auto-update channel (signed updates)
- [ ] Installer + uninstaller
- [ ] Settings & exclusions UI
- [ ] Performance tuning + release packaging (PyInstaller)
