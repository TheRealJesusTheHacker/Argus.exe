# ARGUS.EXE — Roadmap

**Vendor:** Sentinel Safeguard LLC
**Tagline:** Security For Everyone.
**Platform:** Windows (.exe)

Argus is **not** a portable download-and-run scanner. It installs on
the machine and becomes its default security app: always on, running
from boot, registered with Windows as the system's antivirus provider.

Every detection carries a **severity** — Critical / High / Medium /
Low — on top of the file's overall verdict. Signature hits inherit the
signature's severity; pattern-rule and heuristic signals carry their
own. Severity drives what Argus does next (Phase 4 actions).

## Phase 1 — Detection engine ✅ (v0.2.0)
- [x] File walker (recursive, symlink-safe, permission-error tolerant)
- [x] SHA-256 hashing pipeline (streamed, no whole-file loads)
- [x] Signature database format (JSON/SQLite) + loader + integrity check
- [x] Pattern rules (YARA-style) evaluation
- [x] CLI: `argus scan <path>` with plain-language results

## Phase 2 — Heuristics ✅ (v0.3.0)
- [x] Entropy analysis (packed/encrypted payload detection) — whole
      file + sliding-window regions + per-section, streamed
- [x] PE header/import inspection — pure-stdlib parser: sections,
      imports, exports, TLS callbacks, signature presence, overlay
- [x] Suspicious behavior signals (persistence, injection, credential
      access, keylogging, download-and-execute, masquerading,
      packers, script/LOLBin abuse) — each weighted, each explained
      in plain language, each carrying its own severity
- [x] Risk scoring model (clean / suspicious / malicious) — weighted
      points, critical-combination short-circuit, signature discount
      that lowers but never erases; every point traceable to a named
      signal

## Phase 3 — Real-time protection
- [ ] Filesystem watcher (on-write scanning) — an always-on background
      component, designed from the start to become a Windows service:
      starts at boot, runs before any user logs in
- [ ] Process monitor (on-execute scanning, pre-execution block)
- [ ] Download/execute interception points

## Phase 4 — Quarantine, actions & reporting
- [ ] Per-severity **actions** on malicious files, matched to the
      detection's severity:
  - **Quarantine** — move to the encrypted vault, reversible
  - **Permanent delete** — for confirmed malicious files
  - **Allow / ignore** — user vouches for a file; Argus stands down
- [ ] Every action is **user-confirmed, never silent** — Argus never
      deletes or quarantines anything behind the user's back
  (Critical-severity pre-execution *blocking* in Phase 3 prevents a
  run; it does not remove the file.)
- [ ] Restore / remove flows for quarantined files
- [ ] Detection explanations in plain language
- [ ] Scan history + audit log

## Phase 5 — Product: premium GUI, Dev Toolkit, install & default security app
### Premium GUI
- [ ] Sentinel green/black, premium standard — a modern product
      interface, not a dated toolkit look
- [ ] Dashboard: protection status, last scan, detections by severity
- [ ] Scan controls, quarantine manager, reports

### Dev Toolkit panel
- [ ] Heuristic sensitivity control
- [ ] Per-signal enable/disable and weight tuning
- [ ] Exclusions manager
- [ ] Rule test bench — run a file against rules/signals and see the
      full scoring breakdown
- [ ] Verbose logging toggle
- [ ] Simulation mode — detect-only, no actions taken
- [ ] Self-test (EICAR) — verify the whole pipeline on demand

### Install & default security app
- [ ] Proper Windows installer: Program Files layout, Start Menu,
      clean uninstaller
- [ ] Background service: auto-starts at boot (the Phase 3 watcher
      graduates into it), tray-resident supervision
- [ ] System tray presence: live status + quick actions (scan now,
      open quarantine, pause/resume)
- [ ] **Windows Security Center registration**
      (`root\SecurityCenter2` AntiVirusProduct) so Windows
      recognizes Argus as the system's antivirus provider
- [ ] Signature auto-updates running as a service task
