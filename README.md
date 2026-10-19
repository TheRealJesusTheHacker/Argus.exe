<p align="center">
  <h1 align="center">ARGUS.EXE</h1>
  <p align="center"><strong>All eyes. All detection.</strong></p>
  <p align="center">Antivirus &amp; malware detection by <strong>Sentinel Safeguard LLC</strong></p>
  <p align="center"><em>Security For Everyone.</em></p>
</p>

---

## What is Argus?

In Greek myth, **Argus** was the hundred-eyed giant — nothing escaped his gaze. **ARGUS.EXE** carries that name for the same reason: a watcher that never blinks.

Argus is Sentinel Safeguard LLC's antivirus and malware detector for Windows and Linux. It is built for the people enterprise security forgot — home users, single-PC shops, and small businesses that need real protection without a per-seat enterprise contract, a bloated install, or a sales call.

**Two editions, one product:** the Windows edition (`Argus.exe`, a single self-installing file) and — new in v1.2.0 — the Linux edition (`Argus.deb`) for Debian-based systems: **Kali Linux, Parrot OS, Debian, and Ubuntu**. The Linux edition is the same product translated to its platform, not a port of leftovers: a systemd protection service instead of the Windows service, a kernel-verified Unix socket instead of the named pipe, inotify watching instead of polling, and dpkg package records standing where Windows uses code signatures. The detection engine — signatures, heuristics, behaviour rules, the encrypted vault — is shared, line for line.

## What it does

- **Signature scanning** — known-malware detection against a curated signature database (hashes + pattern rules), updated regularly.
- **Heuristic & behavioral watch** — unknown threats caught by what they *do*, not just what they're *named*: suspicious process chains, persistence tricks, ransomware-style file churn.
- **Real-time protection** — files watched as they're written, downloaded, or executed; threats stopped before they run.
- **Quarantine** — detected threats are isolated safely, never silently deleted. Review, restore, or remove on your terms.
- **Plain-language reporting** — every detection explained in words a person can act on, with a full scan history and clean audit trail.
- **It knows itself** — Argus never scans its own program or its own data (the quarantine vault holds neutralised threat samples; scanning them would be noise). The exemption is by *identity*, never by name: the program file is skipped only when it provably is Argus (the running program, the copy registered with Windows, or the fingerprint recorded at setup). A file merely *named* `Argus.exe` anywhere else is scanned like any stranger — and a file sitting at Argus's own address that fails the identity check is scanned in full and reported as a tamper indicator.
- **It knows Windows** — a file with a structurally valid Microsoft signature, living in its proper place under the Windows folder, is recognised as a system file: its behaviour-based suspicion is cleared (normal system files do system things). The findings stay listed on the report — nothing is hidden — and the recognition clears *only* behaviour suspicion: a signature-database match or pattern-rule detection on the same file still stands in full.
- **It knows Linux** — the same recognition, in the platform's own terms: a file the package manager (dpkg) records as an installed package's own file, living in a system location (`/usr`, `/bin`, `/sbin`, `/lib*` — never `/usr/local` or a home folder), is recognised as a system file with the same limits: behaviour suspicion cleared, findings still listed, signature and rule detections fully in force. And the Linux service verifies who is asking for privileged actions exactly as strictly as the Windows one — the kernel itself (SO_PEERCRED) vouches for the calling process, which must prove it is the genuine installed Argus program by its recorded SHA-256 fingerprint.

## Design principles

1. **Security For Everyone.** No enterprise gatekeeping. If it runs Windows, it deserves protection.
2. **Lightweight.** Protection shouldn't eat the machine it's protecting.
3. **Honest.** Argus says what it found, why it flagged it, and what it did — no scareware tactics, no fake "threats detected" upsells. Ever.
4. **User in control.** Quarantine-first. Nothing is deleted behind your back.

## Development phases

| Phase | Scope |
|-------|-------|
| **Phase 1 — Detection engine** | Core scanner: file walking, hashing (SHA-256), signature database format + loader, YARA-style pattern rules. CLI scan. |
| **Phase 2 — Heuristics** | Behavioral rules engine: entropy analysis, PE inspection, suspicious API/import patterns, packer detection. Risk scoring. |
| **Phase 3 — Real-time watch** | Filesystem watcher with write-debounce + process monitor, built as an always-on background component that becomes a Windows service (starts at boot). |
| **Phase 4 — Quarantine & actions** | Encrypted quarantine vault, per-severity actions (quarantine / delete / allow), scan reports, detection explanations, history/audit log. Every action user-confirmed — never silent. |
| **Phase 5 — Product** | Premium GUI (Sentinel green/black) with a Dev Toolkit panel, background service with system tray, Windows Security Center registration as the system's antivirus, signature auto-updates. Since v1.1.0 the installer is Argus itself: one self-installing `Argus.exe`, no separate installer (the earlier installer is retired). Argus installs and becomes the machine's default security app — not a portable scanner. |

## Status

**Current version: 1.2.0** (see `argus/__init__.py` and `pyproject.toml`). The defining change of this release:

**v1.2.0 — the Linux edition.** Argus now ships for Debian-based Linux as `Argus.deb`, built for **Kali Linux and Parrot OS** (and Debian/Ubuntu): install it with apt and the `argus-protection` systemd service starts protecting the machine — real-time watching via inotify, the same scanner, heuristics, rules and encrypted vault, the same window. The platform translation is conservative in the same places the Windows edition is: privileged actions (quarantine / delete / restore / whitelist) travel over a Unix socket where the kernel vouches for the caller (SO_PEERCRED) and the caller must match the installed program's recorded fingerprint — a file-drop request alone can never carry them, exactly as on Windows; Argus recognises itself by recorded identity, never by name; and dpkg-owned system files in system locations get their behaviour suspicion cleared while signature and rule detections stand. The package is honest about its evidence: it is verified on the project's Linux build VM and CI (full test suite, packaged `--self-check` / `--self-check-qt`, a live daemon run, and a real `dpkg` install with the service running under systemd); the first run on physical Kali/Parrot hardware is the remaining verification step and is tracked as such in `docs/ROADMAP.md` — nothing here claims otherwise. The Windows edition is unchanged in behaviour by this release.

The defining change of the previous line arrived in v1.1.0:

**v1.1.0 — one file that installs itself.** Argus is now a single `Argus.exe`: the app, the protection service, and the setup engine in one file. Download it, open it, choose **Set up protection**, allow the one Windows permission prompt — Argus places itself in `Program Files\Sentinel Safeguard\Argus`, sets up the always-on `ArgusProtection` service, registers with Windows Security, starts protection, and *verifies each of those steps before it calls itself done*. No installer wizard, no separate service download, no command line, nothing to configure to be protected. Uninstalling is just as plain — from the Argus window or Windows Settings — and **keeps your quarantine vault and history** unless you explicitly ask to remove them. This release exists because the v1.0.5 installer's hidden service step silently failed on a real machine (the service was never installed, and the old GUI then dead-ended against the locked vault); v1.1.0 removes that entire class of failure — every setup step is performed by Argus itself, checked, and reported in plain language. Underneath: machine data under `C:\ProgramData\Argus` with the v1.0.4 trust split (the service never trusts user-writable state; the signature database carries an HMAC authenticity tag), so the service and the app always see the same vault and history. The portable edition is the *same* exe in portable mode (ArgusPortable.zip — unzip and run; it never installs, protection runs while the app is open). This build also teaches Argus to recognise **itself** and **Windows**: it never scans its own program or data (by proven identity, never by name — an impostor `Argus.exe` is scanned like any stranger, and a replaced program file is reported as tampering), and it recognises genuine Microsoft-signed system files in their system home, clearing their behaviour suspicion while leaving signature and rule detections fully in force.

The rest of the product, from Phase 5: the premium Sentinel green/black **GUI** (Dashboard, Scan, Quarantine, Pending Actions, History, Settings, and a **Dev Toolkit**), a real **Windows service** (`ArgusProtection`, starts at boot), **Windows Security Center registration** so Argus is listed as the machine's antivirus in Windows Security, a **system tray** presence, and a first-run **onboarding wizard** with an EICAR self-test. The Dev Toolkit is the workbench: detection-sensitivity slider, per-signal enable/weight steering, a rule test bench that dissects any file down to every point of its score, **simulation mode** (detect-only — actions are recorded as intent and nothing is ever touched), verbose logging, and the EICAR self-test. The rules from day one still hold in every layer, GUI included: **nothing happens to your files behind your back** — destructive actions always ask first, and deletion is never automatic under any setting. Honest remainders: the process monitor scans a program *as* it starts (pre-execution blocking and kernel tamper protection need Microsoft's driver signing programs — future work), and the vault's encryption exists to neutralize threats, not to store secrets.

## Install

**From a release (Windows):** download `Argus.exe` from the latest GitHub release and open it. Choose **Set up protection** and allow the Windows permission prompt; Argus installs itself, starts protection, and confirms it's running — that's the whole process. To remove it later, use the uninstall entry in Windows Settings → Apps (or run Argus and use its own uninstall), and your vault and history are kept unless you check "also remove my Argus data". The portable edition (`ArgusPortable.zip`, the same exe) is attached to the same release for carrying Argus on a USB stick; `SHA256SUMS.txt` covers all downloads.

**From a release (Linux — Kali, Parrot, Debian, Ubuntu):** download `Argus.deb` from the same GitHub release and install it the Debian way:

```
sudo apt install ./Argus.deb
```

That's the whole process: the package places the program in `/usr/lib/argus`, its data in `/var/lib/argus`, records the program's fingerprint, and enables + starts the `argus-protection` service; Argus appears in the desktop's application menu (Xfce on Kali, MATE on Parrot). Check protection any time with `argus service status`. Remove it with `sudo apt remove argus` (your vault and history are kept) or `sudo apt purge argus` (everything Argus owns is removed).

**From source:**

```
pip install ".[gui,windows]"     # engine + GUI + Windows service layers (Windows)
pip install ".[gui]"             # engine + GUI (Linux: the platform layer is stdlib)
python -m argus.gui               # the GUI (or: argus-gui)
python -m argus sigdb init        # build a signature database
python -m argus scan <path>       # scan from the command line
python -m argus watch             # real-time protection in the foreground
python -m argus service install   # (Windows, admin) install the service
```

The engine core is pure Python standard library; PySide6 is the GUI layer, pywin32 serves only the Windows service/registration modules, and the Linux platform layer (systemd, the verified socket, inotify, dpkg trust) is standard library too — `ctypes` and `dpkg-query`/`systemctl`, nothing else.

## Usage

- **GUI:** open `Argus.exe` (installed or portable) — Dashboard, Scan, Quarantine, Pending Actions, History, and Settings are all in the main window.
- **CLI:** `python -m argus scan <path>` scans a file or folder; `python -m argus watch` runs real-time protection in the foreground; `python -m argus sigdb init` builds a signature database.
- **Service (Windows, admin):** `python -m argus service install` installs the `ArgusProtection` service from source; the packaged `Argus.exe` sets the same service up itself during "Set up protection".

## How it works

- **Detection layers, in order:** signature matching against the signature database (SHA-256 hashes plus pattern rules), then heuristic analysis — entropy analysis, PE structure inspection, and weighted behaviour signals — combined by the risk-scoring model into a verdict (clean / suspicious / malicious) where every point traces back to a named signal. Every detection also carries a severity (Critical / High / Medium / Low) that drives the action offered.
- **Real-time watch:** a filesystem watcher with write-debounce plus a process monitor that scans a program as it starts. Pre-execution blocking and kernel tamper protection are not claimed — they need Microsoft's driver signing programs and are listed as future work in the Status section above.
- **Quarantine & actions:** detected threats go to the encrypted quarantine vault under `C:\ProgramData\Argus`; actions (quarantine / delete / allow) are always user-confirmed, and deletion is never automatic. Reports explain each detection in plain language, with full scan history and an audit trail.
- **Trust boundaries:** the service never trusts user-writable state, and the signature database carries an HMAC authenticity tag. Argus's self-recognition and Windows system-file recognition work as described under "What it does" — by proven identity, never by name or path alone.
- **Layout:** the detection engine, heuristics, quarantine, real-time watch, service, and reporting live in `argus/` (the Linux platform layer — `linuxservice`, `socket_channel`, `platform_dpkg`, `inotify_watcher`, the FHS half of `paths` — sits beside its Windows twins there); the PySide6 GUI in `argus/gui/`; packaging (the Windows and Linux PyInstaller specs, the `.deb` builder under `packaging/linux/`, the portable launcher) in `packaging/`; the test suite in `tests/`; and the full phase-by-phase plan in `docs/ROADMAP.md`.

## The family

Argus is a Sentinel Safeguard product, alongside **Hellhound.exe** (malware education — see what real malware does, safely announced) and **Cyra** (local AI assistant, formerly J.A.D.E.). Argus is the shield to Hellhound's lesson: one shows you the threat, the other stops it.

## License

Argus is proprietary software of Sentinel Safeguard LLC — see [LICENSE](LICENSE). All rights reserved; no copying, redistribution, resale, or derivative works without prior written permission from Sentinel Safeguard LLC.

---

*Sentinel Safeguard LLC — Kansas City, MO · Security For Everyone.*
