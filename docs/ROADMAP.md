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

## Product pillars

Everything Argus ships is judged against four pillars:

1. **Maximum detection power.** Catch what others miss — signatures,
   heuristics, behaviour, and every layer in the detection-depth
   backlog below. A scanner that politely misses malware is a liar
   with a progress bar.
2. **Maximum functionality.** Real protection, real control: scanning,
   real-time watch, quarantine, exclusions, a Dev Toolkit — the whole
   tool, not a demo with the good parts paywalled off.
3. **Premium look and feel.** Sentinel green/black, built to a
   premium standard in every surface — GUI, CLI output, reports,
   messages. If it looks cheap, it ships broken.
4. **Enjoyable to use.** Argus may ship free or paid (TBD) — either
   way, the experience must be one people *enjoy*: fast, clear,
   honest, zero jargon walls, no scareware, no dark patterns. People
   should feel protected, not lectured.

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

## Phase 3 — Real-time protection ✅ (v0.4.0)
- [x] Filesystem watcher (on-write scanning) — an always-on background
      component, designed from the start to become a Windows service:
      starts at boot, runs before any user logs in. Portable polling
      watcher (stdlib only) with **debounce**: a file is scanned only
      once its size/mtime are stable across consecutive polls, so
      half-written downloads are never judged mid-write. Symlinks are
      never followed; vanished/locked files are counted and reported,
      never fatal.
- [x] Process monitor (on-execute scanning) — polling monitor
      (Linux /proc, Windows Toolhelp32) that notices programs starting
      and scans the file each launched from, raising an alert event.
      **Honest limit:** polling detects a launch as it happens; true
      *pre-execution blocking* (stopping the program before it runs)
      arrives with the Phase 5 service/driver work.
- [x] Download/execute interception points — the watched folders are
      exactly the landing zones (Downloads, Desktop, Documents, temp);
      launches are intercepted by the process monitor above.
- [x] Service-ready core — start / stop / pause / resume, config
      reload, JSON heartbeat + status file (`argus watch`,
      `argus watch-status`), clean shutdown on SIGINT/SIGTERM.
      Phase 5 wraps this core as a Windows service (pywin32).
- [x] Response policy — per-severity default actions from config
      (Critical/High → quarantine request, Medium → alert, Low →
      log). Phase 3 *emits* action events only; the file moves
      themselves are Phase 4 and always user-confirmed.
- [x] Configuration + exclusions — JSON config with tolerant loading
      (bad config → defaults + loud warnings, never a crash);
      exclusions by path and by SHA-256, honoured in real-time AND
      on-demand scans.

## Detection-depth backlog (future)
Depth Argus grows into after the core product ships — pillar 1
(maximum detection power) made concrete:

- [ ] **Fuzzy hashing** (ssdeep/TLSH-style) — catch *variants* of
      known malware, not just byte-identical copies
- [ ] **Archive scanning** — threats arrive zipped: look inside
      .zip (and kin) during scans, with zip-bomb limits
- [ ] **Document & macro scanning** — Office/PDF carriers, macro
      droppers, embedded-object inspection
- [ ] **Scan modes** — scheduled scans plus quick / full / custom
      modes for on-demand runs
- [ ] **Removable-media auto-scan** — USB drives and cards scanned
      on insertion
- [ ] **Community signature feeds** — import public hash feeds
      (e.g. abuse.ch MalwareBazaar) into the signature DB builder,
      with the same integrity checks as local builds

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
- [ ] **The bar is premium AND approachable:** first-run onboarding
      that gets a new user protected in minutes, a clean dashboard
      that answers "am I safe?" at a glance, and **zero jargon
      walls** — every term explained in plain language or not shown
      at all. Premium must never mean intimidating.
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
