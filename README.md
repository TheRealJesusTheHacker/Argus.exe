<p align="center">
  <h1 align="center">ARGUS.EXE</h1>
  <p align="center"><strong>All eyes. All detection.</strong></p>
  <p align="center">Antivirus &amp; malware detection by <strong>Sentinel Safeguard LLC</strong></p>
  <p align="center"><em>Security For Everyone.</em></p>
</p>

<p align="center">
  <a href="https://github.com/TheRealJesusTheHacker/Argus.exe/releases/latest"><img src="https://img.shields.io/github/v/release/TheRealJesusTheHacker/Argus.exe?style=flat-square" alt="Latest release"></a>
  <a href="https://github.com/TheRealJesusTheHacker/Argus.exe/actions/workflows/build-windows.yml"><img src="https://github.com/TheRealJesusTheHacker/Argus.exe/actions/workflows/build-windows.yml/badge.svg" alt="build-release workflow status"></a>
  <a href="https://github.com/TheRealJesusTheHacker/Argus.exe/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-Proprietary-red?style=flat-square" alt="License: Proprietary"></a>
  <a href="https://www.python.org"><img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?style=flat-square" alt="Python 3.11 or newer"></a>
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-0078D6?style=flat-square" alt="Platforms: Windows and Linux">
  <a href="https://doc.qt.io/qtforpython-6/"><img src="https://img.shields.io/badge/GUI-PySide6-41CD52?style=flat-square" alt="GUI: PySide6"></a>
</p>

---

## Overview

In Greek myth, **Argus** was the hundred-eyed giant — nothing escaped his gaze. **ARGUS.EXE** carries that name for the same reason: a watcher that never blinks.

Argus is Sentinel Safeguard LLC's antivirus and malware detector for Windows and Linux. It is built for the people enterprise security forgot — home users, single-PC shops, and small businesses that need real protection without a per-seat enterprise contract, a bloated install, or a sales call.

Argus is **not** a portable download-and-run scanner that you open once and forget. On Windows it installs itself, starts at boot as a service, and registers with Windows Security Center as the machine's antivirus provider. A portable edition exists for carrying Argus on a USB stick, and it is honest about what it does not do (see [Editions](#editions)).

**Two editions, one product:**

- **Windows** — `Argus.exe`, a single self-installing file, plus `ArgusPortable.zip`, the same executable in portable mode.
- **Linux** — `Argus.deb` for Debian-based systems: **Kali Linux, Parrot OS, Debian, and Ubuntu** (new in v1.2.0).

The Linux edition is the same product translated to its platform, not a port of leftovers: a systemd protection service instead of the Windows service, a kernel-verified Unix socket instead of the named pipe, inotify watching instead of polling, and dpkg package records standing where Windows uses code signatures. The detection engine — signatures, pattern rules, heuristics, risk scoring, the encrypted vault — is shared.

| | |
|---|---|
| **Current release** | v1.2.8 — see [Status](#status) and the [release page](https://github.com/TheRealJesusTheHacker/Argus.exe/releases/latest) |
| **Release assets** | `Argus.exe`, `ArgusPortable.zip`, `Argus.deb`, `SHA256SUMS.txt` (one checksum file covering all three downloads) |
| **Requirements (source)** | Python 3.11 or newer; the engine core is pure Python standard library |
| **Optional layers** | PySide6 for the GUI; pywin32 for the Windows service and Security Center registration (Windows only) |
| **License** | Proprietary — see [License](#license) |

## Features

- **Signature scanning** — known-malware detection against a curated SQLite signature database (SHA-256 hashes) that carries an HMAC-SHA256 authenticity tag and is integrity-checked on load. A freshly built database is seeded with the industry-standard, harmless EICAR test file so the whole pipeline can be verified end to end.
- **Pattern rules** — YARA-style pattern rules evaluated alongside the hash database; a rule hit is a detection in its own right and is never cleared by any trust recognition.
- **Heuristic analysis** — entropy analysis (whole-file, sliding-window, and per-section), a pure-standard-library PE parser (sections, imports, exports, TLS callbacks, signature presence, overlay), and a catalog of 43 weighted behaviour signals in `argus/devtools.py` covering persistence, process injection, credential access, keylogging, download-and-execute, masquerading, packers, and script / LOLBin abuse. Every signal is weighted, carries its own severity, and is explained in plain language.
- **Risk scoring you can audit** — signals add up to a verdict: **Clean** below 25 points, **Suspicious** from 25–59, **Malicious** at 60 or more. A critical signal combination short-circuits straight to Malicious, and a digital signature trims points but never erases a score to Clean and never cancels a critical combination. Every point traces back to a named signal — no opaque math.
- **Severity on every detection** — Critical / High / Medium / Low, on top of the verdict. Signature hits inherit the signature's severity; rule and heuristic detections carry their own. Severity drives the action Argus offers.
- **Real-time protection** — folders where threats land (Downloads, Desktop, Documents, temp by default) are watched as files are written, and a process monitor scans a program as it starts. On Linux an inotify backend feeds the same debounce logic; if inotify is unavailable the watcher falls back to polling and reports that honestly in its status.
- **Encrypted quarantine vault** — detections are isolated, never silently deleted. The vault uses authenticated encryption (an HMAC-SHA256 keystream, encrypt-then-MAC, pure standard library): a blob is verified end to end before the original file is removed, and a tampered blob refuses to restore. Restore never overwrites a file that has taken the original's place.
- **Actions always ask first** — quarantine, permanent delete, and allow / ignore all go through an explicit confirmation. **Deletion is never automatic under any policy or setting.** The most a real-time policy may do unattended is quarantine a Critical file — and only when the user has configured exactly that.
- **Pending-actions queue** — under the default `ask` policy, real-time action requests wait for a human approve / reject decision instead of acting on their own.
- **Plain-language reporting** — every detection is explained in words a person can act on. Every scan, manual and real-time, is recorded in a SQLite history with an audit trail; `argus report` and `argus history` render it as text or JSON.
- **Premium GUI** — a PySide6 interface in Sentinel green/black with seven pages — Dashboard, Scan, Quarantine, Pending Actions, History, Settings, and a Dev Toolkit — plus a system tray presence and a first-run onboarding wizard with an EICAR self-test.
- **Dev Toolkit** — the workbench inside the GUI: a heuristic-sensitivity slider, per-signal enable / weight steering (kept identical to the engine's signal library by a drift-guard test), an exclusions manager, a rule test bench that breaks a file's score down signal by signal, verbose logging, simulation mode (detect-only; actions are recorded as intent and nothing on disk is touched), and the EICAR self-test.
- **It knows itself** — Argus never scans its own program or its own data (the quarantine vault holds neutralised threat samples; scanning them would be noise). The exemption is by *identity*, never by name: the program file is skipped only when it provably is Argus — the running program, the copy registered with the service manager, or the fingerprint recorded at setup. A file merely *named* `Argus.exe` anywhere else is scanned like any stranger, and a file sitting at Argus's own address that fails the identity check is scanned in full and reported as a tamper indicator.
- **It knows Windows** — a file is recognised as a trusted system file only when all three hold: a valid Authenticode signature (verified by Windows itself through WinVerifyTrust, which fails closed on Windows), a Microsoft signer, and a home under the Windows folder. Recognition zeroes the *heuristic* score only — the findings stay listed on the report with an explanatory note, and a signature-database match or pattern-rule detection on the same file still stands in full.
- **It knows Linux** — the same recognition in the platform's own terms: a file is a system file when dpkg records it as an installed package's own file, its resolved path is a system location (`/usr`, `/bin`, `/sbin`, `/lib*` — never `/usr/local` or a home folder), and, since v1.2.3, its contents still match what the package shipped. The same limits apply: behaviour suspicion cleared, findings still listed, signature and rule detections fully in force. A missing or failing dpkg fails closed.
- **Caller-verified privileged actions** — on an installed system, restore / allow / delete / approve / reject execute only over the verified channel (a named pipe on Windows, a Unix socket on Linux) and only after the service verifies the calling process: its image must resolve to the canonical installed Argus program and hash to the fingerprint recorded at install. On Linux the kernel itself vouches for the peer first (SO_PEERCRED: PID and UID). A dropped request file alone can never carry a privileged action in the installed layout.

## Design principles

1. **Security For Everyone.** No enterprise gatekeeping. If it runs Windows or Debian-based Linux, it deserves protection.
2. **Lightweight.** Protection shouldn't eat the machine it's protecting. The engine core is pure standard library, hashing is streamed, and files are never loaded whole just to be scanned.
3. **Honest.** Argus says what it found, why it flagged it, and what it did — no scareware tactics, no fake "threats detected" upsells, and no capability claims the code doesn't back. Known limits are written down in this README and in `docs/ROADMAP.md`, not buried.
4. **User in control.** Quarantine-first. Nothing is deleted behind your back, under any setting.

## Editions

| Edition | Asset | How it runs | Always-on service | Security Center registration |
|---|---|---|---|---|
| Windows, installed | `Argus.exe` | Download, open, choose **Set up protection**, allow the single UAC prompt | Yes — `ArgusProtection`, starts at boot | Yes |
| Windows, portable | `ArgusPortable.zip` | Unzip, launch `Argus-Portable.bat`; settings, vault, and history live in the `ArgusData` folder beside it | No — real-time protection runs while the app is open | No |
| Linux | `Argus.deb` | `sudo apt install ./Argus.deb` | Yes — `argus-protection` (systemd) | No Linux equivalent exists; not claimed |

The installed Windows edition is **one self-installing file**: the GUI, the protection service, and the setup engine are all in `Argus.exe`. There is no separate installer — the Inno Setup installer used before v1.1.0 is retired. During setup Argus places itself in `Program Files\Sentinel Safeguard\Argus`, stores machine data under `C:\ProgramData\Argus`, installs and starts the service, registers with Windows Security Center, and **verifies each step before it calls itself done** — no step may fail silently.

## Install

### Windows — from a release

1. Download `Argus.exe` from the [latest release](https://github.com/TheRealJesusTheHacker/Argus.exe/releases/latest). Optionally verify it against `SHA256SUMS.txt` from the same release.
2. Open it and choose **Set up protection**.
3. Allow the one Windows permission (UAC) prompt. Argus installs itself, starts protection, and confirms it is running — that is the whole process.

To remove it later, use the uninstall entry in Windows Settings → Apps, or Argus's own uninstall in the app. Your quarantine vault and history are kept unless you check "also remove my Argus data".

**Portable:** download `ArgusPortable.zip` from the same release, unzip it anywhere (a USB stick works), and launch `Argus-Portable.bat` — not `Argus.exe` directly, because the launcher is what points Argus at its portable `ArgusData` folder. Portable Argus never installs anything; delete the folder and it is gone.

### Linux — from a release (Kali, Parrot, Debian, Ubuntu)

```bash
sudo apt install ./Argus.deb
```

That is the whole process: the package places the program in `/usr/lib/argus`, its data in `/var/lib/argus`, its configuration in `/etc/argus`, records the program's fingerprint, and enables and starts the `argus-protection` service. Argus appears in the desktop application menu (Xfce on Kali, MATE on Parrot). Check protection any time with:

```bash
argus service status
```

Remove it with `sudo apt remove argus` (vault and history are kept) or `sudo apt purge argus` (everything Argus owns is removed).

### From source

Requires Python 3.11 or newer.

```bash
pip install ".[gui,windows]"   # engine + GUI + Windows service layers (Windows)
pip install ".[gui]"            # engine + GUI (Linux: the platform layer is stdlib)
python -m argus.gui             # the GUI (or: argus-gui)
python -m argus sigdb init      # build a signature database
python -m argus scan <path>     # scan from the command line
python -m argus watch           # real-time protection in the foreground
python -m argus service install # (Windows, admin) install the service
```

The engine core is pure Python standard library; PySide6 is the GUI layer, pywin32 serves only the Windows service / registration modules, and the Linux platform layer (systemd, the verified socket, inotify, dpkg trust) is standard library too — `ctypes` and `dpkg-query` / `systemctl`, nothing else.

## Usage

### GUI

Open `Argus.exe` (installed or portable) on Windows, or launch Argus from the application menu on Linux. The main window has seven pages:

- **Dashboard** — protection status, last scan, and detections by severity: "am I safe?" at a glance.
- **Scan** — scan a file or folder on demand and read the result, signal by signal.
- **Quarantine** — review vault entries; restore or remove them, always through the confirmation flow.
- **Pending Actions** — real-time action requests waiting for your approve / reject decision.
- **History** — past scans and detections, with the plain-language explanation each one carried.
- **Settings** — watched folders, exclusions (by path and by SHA-256 fingerprint), per-severity actions, and the real-time policy.
- **Dev Toolkit** — sensitivity and per-signal tuning, the rule test bench, simulation mode, verbose logging, and the EICAR self-test.

The system tray icon shows live protection state and offers quick actions (scan now, open quarantine, pause / resume). The first launch shows a one-time onboarding wizard that ends with the EICAR self-test, so a new user can watch the whole detection pipeline work before trusting it.

### CLI

The CLI entry point is `argus` (or `python -m argus` from source):

| Command | What it does |
|---|---|
| `argus scan <path>` | Scan a file or folder. Options include `--db`, `--rules`, `--no-heuristics`, `--config`, `--quarantine` / `--delete` (explicit post-scan actions on Malicious files, via the vault), `--vault-dir`, `--history-db`, and `--json` for machine-readable output. |
| `argus watch` | Run real-time protection in the foreground. |
| `argus watch-status` | Show real-time protection status from the service heartbeat. |
| `argus service <action>` | Manage the protection service: `install`, `uninstall`, `start`, `stop`, `restart`, `status`, `run`, `register`, `unregister`. On Linux, install / uninstall belong to apt; `status`, `start`, `stop`, and `restart` work against systemd. |
| `argus sigdb init` / `argus sigdb info` | Create a signature database (seeded with EICAR), or show an existing database's details. |
| `argus quarantine list` | List vault entries. |
| `argus quarantine restore` / `delete` / `allow` | Put a quarantined file back, permanently delete it, or restore it and vouch for it (adds an exclusion). |
| `argus pending …` | Review and decide actions waiting in the pending-actions queue. |
| `argus report` / `argus history` | Plain-language report of Argus activity and recent scans / detections (JSON export available). |
| `argus --version` | Print the version (`1.2.8`). |

## How it works

**Detection layers, in order.** A file is hashed (SHA-256, streamed) and matched against the signature database; pattern rules are evaluated; then heuristic analysis runs — entropy, PE structure, and the weighted behaviour signals — and the scoring model combines the heuristic signals into a verdict. Every detection also carries a severity (Critical / High / Medium / Low) that drives the action offered. Signature and rule detections decide on their own and are never cleared by trust recognition.

**Real-time watch.** The watcher uses write-debounce: a file is scanned only once its size and modification time are stable across consecutive polls, so half-written downloads are never judged mid-write. Symlinks are never followed; vanished or locked files are counted and reported, never fatal. A process monitor (Toolhelp32 on Windows, `/proc` on Linux) notices programs starting and scans the file each launched from. On Linux, inotify supplies the change feed for the same debounce logic, with an honest polling fallback.

**Quarantine and actions.** Detected threats go to the encrypted vault (under `C:\ProgramData\Argus` on Windows, `/var/lib/argus` on Linux). The action layer raises without an explicit confirmation token — there is no code path where Argus quietly moves or deletes a user's file, and deletion routes through the vault first so the index keeps the audit record even then.

**Trust boundaries.** The protection service never trusts user-writable state: machine data uses a trust split in which the signature database carries an HMAC authenticity tag, privileged actions are caller-verified over the pipe / socket channel described under [Features](#features), and legacy queue records migrate only when their provenance can be proven against the vault itself. Self-recognition and system-file recognition work by proven identity — resolved path plus recorded fingerprint, valid Microsoft signature plus system location, dpkg ownership plus system location plus content match — never by filename.

**Repository layout.**

| Path | Contents |
|---|---|
| `argus/` | The product: scanner, signatures, rules, scoring, quarantine, actions, reporting, real-time engine, service hosts, setup engine, and the platform layers — `winservice` / `winregister` / `pipe_channel` / `platform_authenticode` for Windows, `linuxservice` / `socket_channel` / `platform_dpkg` / `inotify_watcher` for Linux, with `paths` and `selftrust` shared. |
| `argus/heuristics/` | Entropy analysis, the PE parser, and the behaviour-signal library. |
| `argus/gui/` | The PySide6 GUI: main window, dashboard, scan page, management pages, settings and Dev Toolkit pages, onboarding wizard, tray, and theme. |
| `packaging/` | The Windows and Linux PyInstaller specs, the portable launcher (`packaging/portable/`), and the Debian packaging under `packaging/linux/` (control file, maintainer scripts, systemd unit, desktop entry, `build-deb.sh`). |
| `tests/` | The pytest suite (46 test modules). |
| `docs/ROADMAP.md` | The full phase-by-phase product record and the detection-depth backlog. |
| `.github/workflows/build-windows.yml` | The `build-release` workflow: builds and smoke-tests both platform editions on release and attaches the assets and the single `SHA256SUMS.txt`. |

## Configuration

Argus runs correctly with no configuration at all. Settings live in a JSON file (`argus-config.json` in the Argus data folder) that a person can read and edit; the GUI and the `argus` services read the same file. Loading is tolerant by design: an unreadable value falls back to its default **per key**, every problem is collected as a loud warning, and a bad config never crashes protection.

The keys Argus itself writes (from `argus/config.py`):

| Key | Meaning | Default |
|---|---|---|
| `watch_dirs` | Folders real-time protection watches | Downloads, Desktop, Documents, and the system temp folder |
| `poll_interval_seconds` | Filesystem polling interval | `1.0` |
| `stable_polls` | Consecutive unchanged polls before a file is judged stable and scanned | `2` |
| `process_monitor_enabled` / `process_poll_interval_seconds` | On-execute scanning of newly started programs | enabled / `2.0` |
| `heartbeat_interval_seconds` | How often the service writes its status heartbeat | `5.0` |
| `heuristics` | Turn heuristic analysis on or off | `true` |
| `severity_actions` | Default action per severity | Critical / High → `quarantine`, Medium → `alert`, Low → `log` |
| `realtime_default` | How real-time action requests are handled: `ask`, `auto-quarantine-critical`, or `log-only` | `ask` |
| `exclusions` | `paths` and SHA-256 `hashes` Argus leaves alone — honoured by real-time and on-demand scans alike | empty |
| `max_realtime_file_size_mb` | Largest file the real-time engine will scan | `256` |
| `max_dwell_seconds` | A file that keeps changing is scanned anyway after this long | `30.0` |
| `signature_db`, `rules_file` | Signature database and optional extra / replacement rules file locations | data-folder defaults |
| `vault_dir`, `history_db`, `pending_db` | Vault, history, and pending-actions locations | standard data-folder locations |
| `onboarding_completed` | Set once the first-run wizard has been finished, so it shows exactly once | `false` |

Exclusions added by choosing **Allow** are merged into the on-disk config rather than overwriting it, so a vouch made in one Argus window is never silently erased by a save from another.

## Development

```bash
git clone https://github.com/TheRealJesusTheHacker/Argus.exe.git
cd Argus.exe
pip install ".[gui]"        # add the "windows" extra on Windows
python -m pytest            # the full suite
```

The suite's size depends on whether the GUI layer is importable, because the GUI tests skip themselves when PySide6 is absent. Verified on a fresh checkout of v1.2.6:

- **System Python (no Qt): 727 passed, 28 skipped** — `python -m pytest -q` with the standard-library engine only; the skips are the Qt-dependent tests.
- **Windows CI (release gate): the full suite ran green on `windows-latest` in the v1.2.6 release build (run `39448079078`)** — the same run that built the shipped v1.2.6 assets; its test step covers everything below alongside the v1.2.5 correction tests (the six measured bundle profiles, the rebuilt one-file-packaging fixture, the calibration safety invariants) and the v1.2.4 field-fix tests (35).
- **GUI environment (PySide6 venv, `QT_QPA_PLATFORM=offscreen`): 779 passed, 1 skipped** — verified at v1.2.6; the same suite with the GUI layer present, including the GUI smoke, theme, and setup tests.

State a count only if you have just run the suite and seen the summary line — the numbers above are the ones from the runs quoted, not a target.

Releases are built by the `build-release` GitHub Actions workflow (`.github/workflows/build-windows.yml`) when a release is published: the Windows job builds `Argus.exe` and `ArgusPortable.zip` with PyInstaller and smoke-tests the packaged binary (`--self-check`, and `--self-check-qt` offscreen); the Linux job builds `Argus.deb`, inspects the package with `dpkg-deb`, verifies the systemd unit, and runs the same packaged self-checks; a final job then publishes the single `SHA256SUMS.txt` covering all three assets.

## Status

**Current version: 1.2.8** (`argus/__init__.py` and `pyproject.toml` agree). All five development phases in `docs/ROADMAP.md` are complete: detection engine, heuristics, real-time protection, quarantine / actions / reporting, and the product phase (premium GUI, Dev Toolkit, service, Security Center registration, self-installing executable, and the Linux edition).

- **v1.2.8** — archive scanning (B-3 Phase 2, decided build order #2 from 2026-10-21). Argus now looks inside archives during scans: ZIP and TAR (including gzip-compressed TAR) members are scanned through the same engine as loose files — extracted by index to generated flat names inside one dedicated temporary folder, never to a path taken from a member name, and never executed. One set of hard budgets is shared by a whole top-level archive, so nesting cannot multiply the allowance: 512 members, 256 MB of extracted bytes, 3 levels of nesting, 30 seconds per member, all enforced while bytes stream. Anything Argus could not check — a budget hit, a damaged or encrypted member, a link it will not follow, data stored on a folder entry — marks the archive **not fully scanned** on every surface (CLI human and `--json` output, scan history, GUI rows, real-time events): it is never reported clean and never silently skipped, and a scan containing one exits with the detections code, not the clean code. A plain gzip file is not an archive and is not opened as one. The release-gate re-audit of this build also closed four presentation defects in the new state (the JSON headline verdict, report-line forging via crafted member names, folder-entry data, and the history report's closing line) and pinned the zip-slip guard by construction in the test suite. No signature, scoring, or verdict behaviour changes for non-archive files.
- **v1.2.7** — the packaged executable gains a headless scan entry point: `Argus.exe scan <path>` (or `--scan`) runs a real scan through the same engine and exit codes as `python -m argus scan` (0 clean, 1 detections, 2 error), with `--json`/`--db`/`--quarantine` and the scan subcommand's other options passed through. Before this release the packaged executable routed a scan launch to the GUI, so a frozen build could never demonstrate a scan of itself or anything else; the Linux console build demonstrates the frozen scan end to end, and on Windows the scan route attaches to the parent console so a terminal launch gets its report. No detection, scoring, or trust behaviour changes.
- **v1.2.6** — the namesake palette. Argus's interface now wears its own identity from the fleet namesake-palette program: Argus Panoptes, the all-seeing giant whose eyes became the peacock's tail — an abyssal teal-black base (`#05100e`), peacock-emerald primary (`#25cc8a`), and a bronze "eye" accent (`#cfa93f`) on the dashboard statistics. This is a visual-identity release only: no behaviour, layout, text, or logic changes, and the detection engine — including v1.2.5's scoring calibration — is untouched. Every text/background pair the stylesheet renders is pinned at WCAG AA (≥ 4.5:1) by `tests/test_gui_theme.py`, which now also pins the palette constants value-for-value; the full screenshot inventory (all seven pages, message box, setup progress dialog, onboarding wizard, tray menu, and the danger states) was re-rendered and pixel-audited — no light surfaces, and no purple anywhere (the one fleet exception is Beerus, by the owner's word; it does not extend to Argus). Danger keeps the fleet red (`#b03a2e` with white text), so the "Delete permanently" button and the signature-database alarm banner read as danger exactly as before. One rendering recalibration rides along: the severity-badge tint alpha rose 0.15 → 0.18, because the new teal panel pulled the yellow "medium" badge tint's rendered hue out of its pinned band; at 0.18 every severity tint stays in band and every severity text keeps ≥ 4.5:1 on its tint. The Windows version resource in the packaging spec matches 1.2.6 on every surface (tuples and strings). Windows CI gate: release build run `39448079078`, all jobs success; all three assets re-downloaded after publishing and re-verified against the published sums, and the portable zip's exe is byte-identical to the standalone. The hardware confirmation from v1.2.4 remains the open step: re-run the first-run wizard's "Prove it works" self-test, and confirm Argus running beside the bundle flags nothing in its own kit.
- **v1.2.5** — the calibration correction. v1.2.4's scoring calibration was aimed at the wrong trait list: its report named the loader's import combination, debugger-detection imports, and packer section names, but when the published bundle files were re-measured with Argus's own analyzer, the traits actually convicting the kit's tools were the shape of one-file packaging itself — a huge overlay carrying the bundled program (15), high-entropy data outside the declared sections (15), a string table past the extraction cap (10), virtual-machine names shipped inside the bundled runtimes (15), and debugger-detection imports (15); one tool (NitroCore) carries an unsigned elevation manifest (15) instead of the VM names. Five tools measured exactly 70 — Malicious — on those traits alone; the sixth (Beerus) measured 55. v1.2.5 extends the calibration to the complete measured list: a profile made only of packaging traits now tops out at Suspicious (the five 70s land at 59; Beerus is unchanged at 55), verified family inside the bundle still scores 0, and real detection is untouched — the packed-injector profile, the critical combinations, and every behavioural signal (download-and-execute, credential access, persistence, keylogging) convict exactly as before, at full weight, the moment any one of them is present. The six measured profiles are pinned verbatim as regression tests (`tests/test_fieldfix_v125.py`), so the calibration is locked to the field data. One related repair: the Windows version resource in the packaging spec was left at 1.2.3 when v1.2.4 was bumped, so the v1.2.4 executable's Properties tab read 1.2.3 — the spec matches the product version again. The hardware confirmation from v1.2.4 remains the open step: after updating, re-run the first-run wizard's "Prove it works" self-test, and confirm Argus running beside the bundle flags nothing in its own kit.
- **v1.2.4** — the field fixes from the first real-machine run of the Technician's Toolkit bundle (2026-10-20), found by the owner on real Windows and fixed the same day. (1) A file Argus cannot read is never waved through as Clean again: when another program — most often the computer's other antivirus software — keeps Argus from reading a file, the scan now says plainly that the file could not be checked, and the first-run self-test answers honestly ("another program kept Argus from reading the test file; Argus cannot prove detection either way") with one automatic retry, instead of reporting a failure of Argus itself. (2) Argus now recognises its own verified family: inside the bundle, a Sentinel tool whose fingerprint matches the bundle's own checksum record is verified family — its program traits stay listed but are not scored against it — while a changed fingerprint on a tool's place is treated as tampering and scanned in full. A file's name still earns nothing. (3) Argus no longer flags itself in portable mode: the "this is the very program that is running" proof now applies wherever the portable program actually lives, not only at the installed address. (4) Scoring calibration: the packaging traits every PyInstaller-built program carries (the loader's import combination, debugger-detection imports, packer section names) corroborate but can no longer convict a file on their own — any real behaviour signal restores full scoring, and the detection corpus (EICAR, the pattern rules, the packed-injector profile, the critical combinations) is unchanged at full strength. (Corrected in v1.2.5, above: this bullet's trait list was incomplete — the traits actually measured on the kit's files were the one-file packaging family, and v1.2.4's calibration never reached them.) One confirmation remains on real hardware, by design: after updating, re-run the first-run wizard's "Prove it works" self-test — it should pass, and Argus running beside the bundle should not flag any tool in its own kit.
- **v1.2.3** — the fixes from the fleet-wide bug-and-security audit of 2026-10-19; no new features, the same product made harder to fool and harder to break. On Linux, a system file now earns trust by its actual contents — a file replaced in place at a trusted path no longer inherits trust it hasn't earned. Folders can no longer silently go unwatched when the system's inotify watch limit is reached — the watcher falls back to a full check and logs it openly. A restore interrupted by a crash or power loss can no longer lock a vault entry forever. Installing a `.deb` upgrade now restarts the protection service, so the new version is the one protecting the machine immediately. The verified channel also caps concurrent sessions, and the Linux service unit gained `NoNewPrivileges`.
- **v1.2.2** — a build fix only: it repaired a wrong file path in the Linux packaging step that left the v1.2.1 release incomplete (its Linux package and checksums never attached). The product was unchanged.
- **v1.2.0** — the Linux edition: `Argus.deb` for Kali, Parrot, Debian, and Ubuntu, with the systemd service, the SO_PEERCRED-verified socket channel, inotify watching, dpkg-based system-file trust, and content-bound self-trust — the Windows design translated, with zero behaviour changes on Windows.
- **v1.1.0** — one self-installing `Argus.exe` (the separate installer and service executable retired), self-recognition and Windows system-file recognition by proven identity, machine data under `C:\ProgramData\Argus` with the trust split, and caller-verified privileged actions over the named pipe.

**Verification status — stated plainly.** The Linux edition is verified on the project's Linux build VM and in CI: the full test suite, the packaged `--self-check` / `--self-check-qt`, a live daemon run, and a real `dpkg` install with the service running under systemd. The first run on physical Kali / Parrot hardware — and the Windows edition's equivalent on-hardware checklist, including Security Center registration on a real machine (the aroura install) — is still pending and is tracked as such in `docs/ROADMAP.md`. Nothing here claims field verification that hasn't happened.

**Known limits, not hidden:**

- Both watchers poll (Linux: inotify-fed, with polling debounce). A file created, executed, and deleted entirely inside one poll interval can complete its run before Argus sees it. Shortening the interval only narrows that window; the real fix is a filesystem minifilter driver, which is in the roadmap backlog below. Argus's copy never claims otherwise.
- The process monitor scans a program *as* it starts. True pre-execution blocking and kernel tamper protection need Microsoft's driver-signing programmes and are future work, not current features.
- The vault's encryption exists to neutralise threats, not to store secrets.
- Signature auto-updates are not shipped: they are deferred until a signed update-feed design (where updates live, how they are signed and verified) exists. The signature database is local today.

**Roadmap** (from `docs/ROADMAP.md` — planned, not shipped): a filesystem minifilter driver; fuzzy hashing (ssdeep / TLSH-style) to catch variants of known malware; document and macro scanning; scheduled scans and quick / full / custom scan modes; removable-media auto-scan; and community signature feeds (for example MalwareBazaar) imported under the same integrity checks as local builds. Full Authenticode verification on Windows shipped in the v1.1.0 fix rounds — on Windows, system-file trust now requires Windows itself to vouch for the signature via WinVerifyTrust, failing closed.

Development history, in one line per phase: Phase 1, detection engine (v0.2.0); Phase 2, heuristics and risk scoring (v0.3.0); Phase 3, real-time protection (v0.4.0); Phase 4, quarantine, actions, and reporting (v0.5.0); Phase 5, the product — GUI, Dev Toolkit, service, registration, and installation.

## The family

Argus is a Sentinel Safeguard product, alongside **Hellhound.exe** (malware education — see what real malware does, safely announced) and **Cyra** (local AI assistant, formerly J.A.D.E.). Argus is the shield to Hellhound's lesson: one shows you the threat, the other stops it.

## License

Argus is proprietary software of Sentinel Safeguard LLC — see [LICENSE](LICENSE). Copyright © 2026 Sentinel Safeguard LLC. All rights reserved; no copying, redistribution, resale, republication, or derivative works without prior written permission from Sentinel Safeguard LLC. The software is provided "as is", without warranty of any kind.

## Contact

**Sentinel Safeguard LLC** — Kansas City, MO · *Security For Everyone.*
Business contact details are published on Sentinel Safeguard's public homepage and business listings.

---

*Sentinel Safeguard LLC — Kansas City, MO · Security For Everyone.*
