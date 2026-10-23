# ARGUS.EXE — Roadmap

**Vendor:** Sentinel Safeguard LLC
**Tagline:** Security For Everyone.
**Platform:** Windows (.exe) and Linux (.deb)

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
- [x] Windows system-file recognition (v1.1.0) — signer identity
      extracted from the structurally-validated certificate
      (bounded stdlib DER walk of the PKCS#7); trust requires ALL
      THREE of valid cert + Microsoft signer ("Microsoft Windows" /
      "Microsoft Corporation", one pinned constant) + a home under
      the Windows folder. Trust zeroes the HEURISTIC score only —
      signals stay listed with an explanatory note, and signature /
      pattern-rule detections are never cleared by it. A Microsoft-
      signed file outside system locations gets no trust. Honest
      limit: this is structural validation + signer-identity
      extraction, not full Authenticode chain/digest verification
      (see backlog) — the system-location gate is what bounds the
      claim; real-world signer strings across Windows versions
      still want field confirmation on real machines.

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
- **Known limit — the hit-and-run window (documented and accepted,
  P1-23).** Both watchers poll. A file that is created, executed,
  and deleted *entirely inside one poll interval* can complete its
  run before Argus ever sees it: the filesystem watcher never
  observes a stable file to scan, and the process monitor may never
  observe the process. Shortening the poll interval only narrows
  the window — it cannot close it, and polling faster burns the
  machine Argus is meant to stay lightweight on. This is an
  inherent limit of the polling design, not a bug being tracked:
  it is accepted for the current product, and Argus's copy must
  never claim otherwise. A filesystem minifilter driver would
  receive file and process events from the kernel as they happen
  — no interval, no window — but see the decision below: it is
  not being built, and this polling posture is permanent.
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
- [x] Self-exclusion (v1.1.0) — Argus never scans its own data tree
      (vault blobs are neutralised samples; the signature DB is
      bookkeeping) or its own program. Consulted inside `scan_file`
      — the one seam shared by on-demand, real-time, and the
      service — before any read. ABUSE-RESISTANT BY DESIGN: the
      program file is exempt only with an identity proof (it is the
      running exe, or the SCM-registered ImagePath, or its SHA-256
      matches the fingerprint setup records in the trusted root);
      a file merely NAMED `Argus.exe` is scanned normally, and a
      stranger at the program's own address is scanned in full and
      flagged with a tamper signal. Results say "skipped: Argus's
      own file" honestly (`exclusion_source`) rather than pretending
      a scan happened.

## Detection-depth backlog (future)
Depth Argus grows into after the core product ships — pillar 1
(maximum detection power) made concrete:

- [ ] **Filesystem minifilter driver** — **CLOSED 2026-10-21,
      decided not to build (B-2).** Reason: kernel code +
      Microsoft attestation is a company-level commitment, not
      backlog; the documented polling posture (P1-23) is
      permanent.

**Decision 2026-10-21 (B-3) — decided build order:** scan modes
first, archive scanning second — spec'd and scheduled as their
own audited phases, NOT started in this wave; nothing in this
bundle was built at decision time. (Archive scanning has since
been built on `main` as B-3 Phase 2 — see the Archive scanning
bullet below; scan modes remain unbuilt.) Community signature feeds are CLOSED (with
B-1). Fuzzy hashing, document/macro scanning, and
removable-media auto-scan remain named roadmap backlog (not
closed, not started).

- [ ] **Fuzzy hashing** (ssdeep/TLSH-style) — catch *variants* of
      known malware, not just byte-identical copies. Backlog
      retained 2026-10-21 (B-3) — not closed, not started.
- [x] **Archive scanning** — threats arrive zipped: look inside
      .zip (and kin) during scans, with zip-bomb limits.
      **Decided build order #2 (2026-10-21, B-3)** — built as
      B-3 Phase 2 on `main` (ZIP and TAR including gzip-compressed
      TAR, shared budgets for members / extracted bytes / nesting
      depth, in `argus/scanner.py`, covered by
      `tests/test_archive_scanning.py`); not yet in a release
      (the latest release is v1.2.7).
- [ ] **Document & macro scanning** — Office/PDF carriers, macro
      droppers, embedded-object inspection. Backlog retained
      2026-10-21 (B-3) — not closed, not started.
- [ ] **Scan modes** — scheduled scans plus quick / full / custom
      modes for on-demand runs. **Decided build order #1
      (2026-10-21, B-3)** — spec'd and scheduled as its own
      audited phase; not started.
- [ ] **Removable-media auto-scan** — USB drives and cards scanned
      on insertion. Backlog retained 2026-10-21 (B-3) — not
      closed, not started.
- [ ] **Community signature feeds** — **CLOSED 2026-10-21
      (B-3, with B-1).** Reason: signature updates ride
      releases; importing public hash feeds depends on the
      signed-feed trust root closed in B-1.
- [x] **Full Authenticode verification (Windows-live)** — chain-of-
      trust + signed digest verification for the system-file
      recognition, via the operating system's own WinVerifyTrust
      (`argus/platform_authenticode.py`, fix round 2): on Windows a
      "trusted system file" verdict now requires Windows itself to
      vouch for the signature; stdlib structural parsing remains
      the gate for reading the claim, never the proof. Off Windows
      (dev machines, the test suite) recognition stays
      structural/claim-based — that fallback is a development
      convenience, not the shipped security posture, and it is
      labelled as such wherever it applies.

## Phase 4 — Quarantine, actions & reporting ✅ (v0.5.0)
- [x] Per-severity **actions** on malicious files, matched to the
      detection's severity:
  - **Quarantine** — move to the encrypted vault, reversible
  - **Permanent delete** — for confirmed malicious files (routes
        through the vault first, so the index keeps the audit record)
  - **Allow / ignore** — user vouches for a file; Argus stands down
- [x] Every action is **user-confirmed, never silent** — Argus never
      deletes or quarantines anything behind the user's back. The
      action layer raises without an explicit confirmation token;
      **deletion is never automatic under any policy** (the most a
      real-time policy may do unattended is quarantine a Critical
      file, and only when the user configured exactly that).
  (Critical-severity pre-execution *blocking* in Phase 3 prevents a
  run; it does not remove the file.)
- [x] Encrypted quarantine vault — pure-stdlib authenticated
      encryption (HMAC-SHA256 keystream, encrypt-then-MAC), opaque
      blob names, streamed I/O, fail-safe ordering: the blob is
      verified end-to-end before the original is removed, and a
      tampered blob refuses to restore. Honest scope: neutralization-
      grade, not a secrets vault.
- [x] Restore / remove flows for quarantined files — restore never
      overwrites a file that took the original's place (restores
      beside it, clearly named)
- [x] Pending-actions queue — real-time requests wait for a human
      approve/reject under the default `ask` policy
      (`realtime_default`: `ask` / `auto-quarantine-critical` /
      `log-only`)
- [x] Detection explanations in plain language — every history
      record carries what was caught, why, and what happened to it
- [x] Scan history + audit log — every scan (manual + real-time)
      recorded in SQLite; `argus report` / `argus history` render
      it in plain language (JSON export too)

## Phase 5 — Product: premium GUI, Dev Toolkit, install & default security app
### Premium GUI
- [x] Sentinel green/black, premium standard — a modern product
      interface, not a dated toolkit look (custom QSS theme +
      drawn widgets: severity badges, score ring, toggle switches;
      `argus/gui/`)
- [x] **The bar is premium AND approachable:** first-run onboarding
      that gets a new user protected in minutes, a clean dashboard
      that answers "am I safe?" at a glance, and **zero jargon
      walls** — every term explained in plain language or not shown
      at all. Premium must never mean intimidating. (Onboarding
      wizard shows once, gated by a config flag.)
- [x] Dashboard: protection status, last scan, detections by severity
- [x] Scan controls, quarantine manager, reports (plus Pending
      Actions and History pages; every destructive button goes
      through the action engine's confirmation flow — GUI dialogs,
      no bypass)

### Dev Toolkit panel
- [x] Heuristic sensitivity control (slider → scoring thresholds)
- [x] Per-signal enable/disable and weight tuning (all 43 signals;
      a drift-guard test keeps the editor's catalog identical to
      the engine's signal library)
- [x] Exclusions manager (paths + SHA-256 fingerprints, in Settings)
- [x] Rule test bench — run a file against rules/signals and see the
      full scoring breakdown (fingerprint, rules, every signal with
      points, entropy, PE facts, final score/verdict)
- [x] Verbose logging toggle (+ in-app log view)
- [x] Simulation mode — detect-only, no actions taken (actions are
      recorded as intent through a simulated engine that cannot
      reach the files; covered by tests)
- [x] Self-test (EICAR) — verify the whole pipeline on demand

### Install & default security app
- [x] Proper Windows installer: Program Files layout, Start Menu,
      clean uninstaller (Inno Setup; uninstall keeps the vault +
      history unless "remove all data" is checked)
      → **Superseded in v1.1.0** by the single self-installing
      `Argus.exe` (below): the Inno installer and the separate
      service exe are retired.
- [x] **One self-installing executable (v1.1.0)**: the GUI, the
      protection service host, and the setup engine in a single
      `Argus.exe` (`argus/entry.py` routes by launch; install runs
      elevated via `--run-setup`). Setup self-places the exe,
      applies the trust-split ACLs, installs the service (ImagePath
      carries the `--service` marker; hosting goes through the
      servicemanager dispatcher), registers with Security Center,
      writes the Add/Remove Programs entry, starts the service,
      and VERIFIES (SCM running + fresh heartbeat) before calling
      itself done. No step may fail silently — the design answer
      to the v1.0.5 hidden-installer-step failure (service never
      installed; proven root causes: pywin32 getopt option order
      + the SCM launch routed to a command the handler lacks).
      Release assets: `Argus.exe`, `ArgusPortable.zip` (the same
      exe in portable mode), `SHA256SUMS.txt`.
- [x] Background service: auto-starts at boot (the Phase 3 watcher
      graduates into it), tray-resident supervision (pywin32
      `ArgusProtection` service via `argus/winservice.py`)
- [x] System tray presence: live status + quick actions (scan now,
      open quarantine, pause/resume)
- [x] **Windows Security Center registration**
      (`root\SecurityCenter2` AntiVirusProduct) so Windows
      recognizes Argus as the system's antivirus provider
      (`argus/winregister.py`, mock-tested; exact productState
      semantics to be confirmed on a real machine)
- [x] **Packaged-executable scan entry (v1.2.7)** — `Argus.exe scan <path>` / `--scan` runs a real headless scan through the CLI engine (`argus.entry` routes to `argus.cli`), so the frozen build can demonstrate a scan (of itself, its kit, or anything else) with the scan's own exit codes. Before v1.2.7 the packaged executable had no scan entry point at all.
- [ ] Signature auto-updates running as a service task —
      **CLOSED 2026-10-21, decided not to build (B-1).** Reason:
      signature updates ride releases (the fleet's shipped
      pattern); a feed's trust root is attack surface built before
      it's needed.
      The packaging/release pipeline (PyInstaller via GitHub
      Actions on release publish) shipped in this phase.

## Fix round 2 (v1.1.0) — who is asking, provenance, honest limits

The fresh-eyes re-audit of the ten-layer hunt fixes found that the
service's action channel authenticated *data* (entry ids,
fingerprints — all published in the service's own snapshots) but
never *the caller*. Round 2 closes that and records the trust
model plainly:

- **Privileged actions are caller-verified in the installed
  Windows layout.** Restore / allow / delete / approve / reject
  execute ONLY when they arrive over the local named pipe in
  `argus/pipe_channel.py`, and only after the service verifies
  the calling PROCESS: the pipe reports the client's PID, whose
  image must resolve to the canonical installed `Argus.exe` AND
  hash to the fingerprint setup recorded in the trusted root.
  File-channel drops of privileged kinds are refused in that
  layout. Confirmation dialogs (GUI and CLI prompts) are built
  from the service's OWN rows, fetched over the same pipe
  ("The protection service reports: …") — the snapshot view
  files are list hints only.
- **The file channel's trust domain is same-user.** In portable,
  dev, and non-Windows layouts the request files remain the
  transport: there, writer and service run as the same user, so
  a process that can write the request can already do anything
  the service's answer would let it do — there is no privilege
  boundary for the pipe to guard. The pipe guards exactly the
  boundary that exists: standard user → LocalSystem, installed
  layout, Windows.
- **Legacy pending migration is provenance-only and one-time.**
  A pre-trust-split queue row migrates only when it references a
  vault entry whose encrypted blob decrypts to the row's exact
  fingerprint — records only the service could have written.
  Everything else is dropped, counted in the service status, and
  announced once in the GUI. A marker file in the trusted root
  makes the pass run exactly once; the earlier "the live file
  hashes to the row" test was removed because a hash is public
  data and proved nothing (a fabricated row naming an arbitrary
  victim file plus its real hash rode it into the trusted queue).
- **BOM-less UTF-16BE scripts — documented and accepted.** A
  script file encoded UTF-16BE *without* a byte-order mark is
  not routed to script content analysis. No mainstream
  interpreter (PowerShell included) executes a BOM-less BE file
  as script — the encodings real droppers use (UTF-16LE with or
  without BOM, UTF-8) are all covered, LE/BE *with* a BOM are
  decoded correctly, and chasing BOM-less BE would mean
  heuristic-guessing an encoding no executor honours. Accepted
  as matching interpreter reality; revisit only if an executor
  that honours BOM-less BE matters.

## Fix round 3 (v1.1.0) — placement independence, pipe hardening

The focused re-audit verified round 2's blockers closed but
found one evasion and six lesser items; all are closed here:

- **UTF-16 routing is placement-independent.** Round 2 routed
  by sampling (head / middle / tail windows); a cradle parked
  BETWEEN the windows of a multi-MB disguised file still scored
  Clean. Routing no longer samples: the scanner tests EVERY
  chunk of its streaming pass for a UTF-16 segment (a fast
  parity-lane test, a few ms per MiB on negative data) and a
  positive at ANY offset triggers a bounded folded second pass
  over the whole file; heuristic routing streams the whole file
  the same way, and the script decoder reads windows around
  located passages parked beyond its head cap. A payload's
  position no longer matters — only its presence.
- **The pipe refuses squatters and sheds silent clients.** It
  is created with FILE_FLAG_FIRST_PIPE_INSTANCE: if another
  process already owns the name, the listener logs loudly and
  does not serve (protection is unaffected; privileged actions
  surface the designed unreachable error). Sessions run on
  their own threads under a 10-second watchdog, so one silent
  client can't starve the channel.
- **Migration rows must also match the entry's own path.** A
  legacy row now migrates only when its path IS the bound
  vault entry's recorded original path, in addition to the
  entry/content binding — fabricated queue items borrowed
  against a real entry are dropped and counted like the rest.
- **Authenticode verdicts are content-keyed.** The verdict
  cache key gained the watcher's sampled content hash, so a
  same-size, mtime-restored replacement re-verifies instead of
  inheriting trust.
- **Prose is not a payload line.** The long-line script signal
  measures the longest whitespace-free run (the encoded-blob
  shape it hunts), and the segment-wise decoder treats an
  encoding seam as a line boundary — a mixed-encoding prose
  document no longer scores Suspicious on its paragraphs.
- **The release smoke covers the first run.** `--self-check`
  now imports the pipe/Authenticode modules and the GUI app /
  onboarding modules, and `--self-check-qt` also constructs
  the onboarding wizard.
- **The oversize script floor no longer flags plain text.**
  The spot audit found the P0-5 floor's false positive: any
  benign UTF-16LE text file over the 4 MB script decode cap
  scored Suspicious 40 on size alone (mismatch 15 + floor 25),
  because all UTF-16 text routes as script. The floor is now
  waived for exactly one shape — content-only routing (no
  script extension; the file never claimed to be code), zero
  rule detections across the full raw + folded streaming
  passes, AND zero heuristic script signals in every decoded
  window actually read. Any rule hit or any script signal
  anywhere keeps the floor; a script extension keeps it
  unconditionally.
- **Known limit — UTF-16 parity flips (documented and
  accepted).** The folded rule views are two streams: bytes at
  even offsets and bytes at odd offsets. A payload whose
  UTF-16LE parity flips MID-NEEDLE — the first half of a
  pattern encoded on even parity, the rest on odd — is whole in
  NEITHER view, so no folded rule can match it. This limit is
  shared with native .ps1 handling (the folded views are the
  UTF-16 mechanism there too) and is accepted, for a precise
  reason: the constructed byte layout is not a valid UTF-16LE
  stream. The flip is a byte inserted or dropped mid-text, so
  an interpreter decoding the file as UTF-16LE reads garbled
  characters at the seam — the needle does not exist as text
  for PowerShell either, and the "payload" cannot execute as
  the script it spells. Argus's decoded-text heuristic signals
  see the same garbled seam an interpreter would. A
  parity-consistent payload at ANY offset is caught (placement
  independence above); only the self-corrupting layout escapes
  the folded views, and it escapes execution the same way.


## Linux edition (v1.2.0) — the .deb for Kali Linux & Parrot OS

The Windows design, translated to Debian-based Linux — not
reinvented. The shared engine (scanner, signature DB, rules,
heuristics, vault cipher, actions, reporting) is unchanged and
pure standard library; only the platform layer is new code.
Zero behaviour changes on Windows.

### What shipped

- **`argus/paths.py`** — the FHS layout beside the Windows
  one: program `/usr/lib/argus/`, data `/var/lib/argus/`,
  config `/etc/argus/`, logs `/var/log/argus/`, runtime
  `/run/argus`. `data_dir()` resolves the installed data root
  only when the installed layout is actually present; the
  `ARGUS_DATA_DIR` override and per-user XDG behaviour are
  untouched. (The Windows canonical-path helpers stay
  platform-blind on purpose — setup tests pin their shape on
  every OS.)
- **`argus/linuxservice.py`** — the systemd sibling of
  `winservice`: a generated unit (`argus-protection.service`,
  `Type=simple` — the daemon runs in the foreground and the
  heartbeat file is the readiness proof, as on Windows;
  `Restart=on-failure`/`RestartSec=5` as the SCM failure-policy
  analog; `RuntimeDirectory=argus` for the socket's home),
  `systemctl` state queries behind the same injectable-runner
  seam, setup-state detection from the layout's own proofs,
  and the management CLI (`argus service status/start/stop/
  restart`; install/uninstall belong to apt). The GUI and the
  daemon share one config-path helper, so they can never read
  different settings.
- **`argus/socket_channel.py`** — the verified privileged
  channel's Linux twin: a Unix domain socket
  (`/run/argus/argus.sock` under systemd) where the service
  verifies the peer from the kernel's own credentials
  (SO_PEERCRED: pid AND uid) and then demands exactly the
  pipe's proof — the peer's image must resolve to the canonical
  installed program AND match the fingerprint recorded at
  install. Sessions run through the SAME session core as the
  pipe (`serve_pipe_stream`, with the verdict injected), so the
  wire behaviour — nonces, refusal wording, designed errors —
  is identical by construction. Root peers are admitted on the
  kernel credential alone (root owns the machine already); a
  squatter holding the socket name is refused without being
  displaced, and a stale socket file is recovered. The file-drop
  request channel stays UNPRIVILEGED-only in the installed
  layout, the same rule as Windows.
- **`argus/platform_dpkg.py`** — system-file trust, Linux
  form: a file is a recognized system file when dpkg records
  it as an installed package's payload AND its resolved path
  is a system location (`/usr`, `/bin`, `/sbin`, `/lib*`;
  `/usr/local` and user folders never qualify). The grant is
  the Windows grant, no wider: the heuristic score is zeroed,
  the findings stay listed with an explanatory note, and
  signature-database / rule detections are never cleared. A
  missing or failing dpkg fails closed. `analyze_file` applies
  the gate on Linux for every routing kind, behind an
  injectable-verifier seam mirroring the Authenticode one.
- **`argus/inotify_watcher.py`** — the realtime watcher's
  Linux backend: inotify via stdlib `ctypes` (no new
  dependency), subclassing the polling watcher so debounce,
  dwell deadline, and signatures are the parent's own code —
  only the change FEED differs (kernel events + a cached
  snapshot; structure changes and queue overflows fall back
  to a full walk). If inotify is unavailable the watcher
  degrades to the parent's polling and SAYS so: the engine
  status (and therefore the service heartbeat) carries
  `watcher_backend`, and it reports "polling", never
  "inotify", when that is what is running.
- **Self-trust** follows the same rules at the FHS address:
  exclusion by the canonical path + the fingerprint the
  package recorded at install (postinst writes
  `self-identity.json` into the root-owned data root on every
  configure, so upgrades re-key trust automatically); a file
  named `argus` anywhere else still scans, and a hash mismatch
  at the canonical path is a tamper signal, scanned + noted.
- **Packaging** (`packaging/linux/`): a PyInstaller spec
  producing the same one-file product (Qt bundled, the Linux
  platform layer as hidden imports), `build-deb.sh` producing
  `dist/Argus.deb` with dpkg-deb, and the Debian tree: control
  (version substituted at build time from `argus.__version__`
  — the source carries `@VERSION@`, never a stale literal),
  postinst (data tree with the vault's permission design —
  quarantine `0700`, request drop `1733` sticky, the rest
  root-owned `0755`; fingerprint recording; enable + start),
  prerm (stop + disable on remove only), postrm (data removed
  only on purge). Desktop entry + icon (the Sentinel eye,
  green on green-black) for Xfce/MATE menus. The checked-in
  unit file is byte-identical to `render_unit()`'s output — a
  test pins it, so the shipped unit cannot drift from the code.
- **CI**: the release workflow gains a Linux job on the same
  tag (full test suite offscreen, .deb build, packaged
  `--self-check` / `--self-check-qt`, package inspection) and
  a final checksums job that publishes ONE `SHA256SUMS.txt`
  covering `Argus.exe`, `ArgusPortable.zip`, and `Argus.deb`.

### Windows → Linux mapping

| Windows | Linux (.deb edition) |
|---|---|
| SCM service `ArgusProtection` | systemd unit `argus-protection.service` |
| SCM failure actions (restart w/ back-off) | `Restart=on-failure`, `RestartSec=5` |
| Named pipe + `GetNamedPipeClientProcessId` caller proof | Unix socket + SO_PEERCRED (pid + uid) |
| Canonical path `C:\Program Files\Sentinel Safeguard\Argus\Argus.exe` | `/usr/lib/argus/argus` |
| `C:\ProgramData\Argus` (ACL'd data root) | `/var/lib/argus` (root-owned; quarantine `0700`, request drop `1733`) |
| Authenticode: Microsoft signature + Windows-folder location | dpkg: package ownership + system location (`/usr`, `/bin`, `/sbin`, `/lib*`) |
| SCM ImagePath as program locator | unit `ExecStart` as program locator (never a proof, same rule) |
| Polling watcher (ReadDirectoryChangesW unused) | inotify via ctypes, honest polling fallback |
| Self-installing `Argus.exe` + ARP registration | `apt install ./Argus.deb`; dpkg's database is the registration |
| Windows Security Center registration | — (no Linux equivalent exists; not claimed) |

### Verification status — read this before quoting it

Verified on the project's Linux VM and CI: the full test
suite (system 645 passed / 28 skipped; GUI 697 passed /
1 skipped — the 48 new platform tests cover real SO_PEERCRED
verification, dpkg decisions against fixtures AND the live
package database, unit generation, maintainer scripts, and
the inotify backend); the built `.deb` inspected
(`dpkg-deb -I`/`-c`); the packaged binary passing
`--self-check` (the frozen Linux census) and
`--self-check-qt` offscreen; `systemd-analyze verify` on the
unit; the packaged daemon running live (heartbeat reporting
`watcher_backend: inotify`, socket listening, clean SIGTERM
shutdown); and a real `dpkg --install` bringing the service
up under systemd, followed by a full purge.

**Still owed — the first real-hardware run** (nothing below is
claimed until it happens on an actual Kali/Parrot machine):

- `sudo apt install ./Argus.deb` on Kali (Xfce) and Parrot
  (MATE): dependency resolution from the distro repos,
  postinst service start on a booted system.
- Service state across a real reboot (enabled at boot,
  heartbeat fresh, `argus service status` agrees).
- Socket verification as a STANDARD user: the GUI running
  unprivileged requests a privileged action; the service
  executes it only via the verified socket, and a forged
  caller (a script, a renamed copy) is refused.
- dpkg trust against the distro's genuine system files (no
  heuristic suspicion on e.g. coreutils binaries; findings
  still listed).
- Menu/tray presence on Xfce and MATE, icon rendering, and
  the onboarding wizard on a real display.
- Windows Security Center registration remains Windows-only
  (there is no Linux analog), and the Windows edition's
  on-hardware checklist is unchanged by this release.
