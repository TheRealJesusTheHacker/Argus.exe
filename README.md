<p align="center">
  <h1 align="center">ARGUS.EXE</h1>
  <p align="center"><strong>All eyes. All detection.</strong></p>
  <p align="center">Antivirus &amp; malware detection by <strong>Sentinel Safeguard LLC</strong></p>
  <p align="center"><em>Security For Everyone.</em></p>
</p>

---

## What is Argus?

In Greek myth, **Argus** was the hundred-eyed giant — nothing escaped his gaze. **ARGUS.EXE** carries that name for the same reason: a watcher that never blinks.

Argus is Sentinel Safeguard LLC's antivirus and malware detector for Windows. It is built for the people enterprise security forgot — home users, single-PC shops, and small businesses that need real protection without a per-seat enterprise contract, a bloated install, or a sales call.

## What it does

- **Signature scanning** — known-malware detection against a curated signature database (hashes + pattern rules), updated regularly.
- **Heuristic & behavioral watch** — unknown threats caught by what they *do*, not just what they're *named*: suspicious process chains, persistence tricks, ransomware-style file churn.
- **Real-time protection** — files watched as they're written, downloaded, or executed; threats stopped before they run.
- **Quarantine** — detected threats are isolated safely, never silently deleted. Review, restore, or remove on your terms.
- **Plain-language reporting** — every detection explained in words a person can act on, with a full scan history and clean audit trail.

## Design principles

1. **Security For Everyone.** No enterprise gatekeeping. If it runs Windows, it deserves protection.
2. **Lightweight.** Protection shouldn't eat the machine it's protecting.
3. **Honest.** Argus says what it found, why it flagged it, and what it did — no scareware tactics, no fake "threats detected" upsells. Ever.
4. **User in control.** Quarantine-first. Nothing is deleted behind your back.

## Build plan

| Phase | Scope |
|-------|-------|
| **Phase 1 — Detection engine** | Core scanner: file walking, hashing (SHA-256), signature database format + loader, YARA-style pattern rules. CLI scan. |
| **Phase 2 — Heuristics** | Behavioral rules engine: entropy analysis, PE inspection, suspicious API/import patterns, packer detection. Risk scoring. |
| **Phase 3 — Real-time watch** | Filesystem watcher with write-debounce + process monitor, built as an always-on background component that becomes a Windows service (starts at boot). |
| **Phase 4 — Quarantine & actions** | Encrypted quarantine vault, per-severity actions (quarantine / delete / allow), scan reports, detection explanations, history/audit log. Every action user-confirmed — never silent. |
| **Phase 5 — Product** | Premium GUI (Sentinel green/black) with a Dev Toolkit panel, a proper Windows installer, background service with system tray, Windows Security Center registration as the system's antivirus, signature auto-updates. Argus installs and becomes the machine's default security app — not a portable scanner. |

## Status

**v1.0.0 — the full product.** Phase 5 completes the build plan: the premium Sentinel green/black **GUI** (Dashboard, Scan, Quarantine, Pending Actions, History, Settings, and a **Dev Toolkit**), a real **Windows service** (`ArgusProtection`, starts at boot), **Windows Security Center registration** so Argus is listed as the machine's antivirus in Windows Security, a **system tray** presence, a first-run **onboarding wizard** with an EICAR self-test, and an **Inno Setup installer** that puts it all in Program Files and sets Argus up as the machine's default security app. The Dev Toolkit is the workbench: detection-sensitivity slider, per-signal enable/weight steering, a rule test bench that dissects any file down to every point of its score, **simulation mode** (detect-only — actions are recorded as intent and nothing is ever touched), verbose logging, and the EICAR self-test. The rules from day one still hold in every layer, GUI included: **nothing happens to your files behind your back** — destructive actions always ask first, and deletion is never automatic under any setting. Honest remainders: the process monitor scans a program *as* it starts (pre-execution blocking and kernel tamper protection need Microsoft's driver signing programs — future work), and the vault's encryption exists to neutralize threats, not to store secrets.

## Install

**From a release (Windows):** download `ArgusSetup.exe` from the latest GitHub release and run it. It installs to `Program Files\Sentinel Safeguard\Argus`, installs and starts the protection service, and registers Argus with Windows Security. Uninstalling removes the program and service but **keeps your quarantine vault and history** unless you check "remove all data" in the uninstaller. Portable `Argus.exe` / `ArgusService.exe` builds are attached to the same release.

**From source:**

```
pip install ".[gui,windows]"     # engine + GUI + Windows service layers
python -m argus.gui               # the GUI (or: argus-gui)
python -m argus sigdb init        # build a signature database
python -m argus scan <path>       # scan from the command line
python -m argus watch             # real-time protection in the foreground
python -m argus service install   # (Windows, admin) install the service
```

The engine core is pure Python standard library; PySide6 and pywin32 are optional layers used only by the GUI and the Windows service/registration modules.

## The family

Argus is a Sentinel Safeguard product, alongside **Hellhound.exe** (malware education — see what real malware does, safely announced) and **J.A.D.E.** (local AI assistant). Argus is the shield to Hellhound's lesson: one shows you the threat, the other stops it.

---

*Sentinel Safeguard LLC — Kansas City, MO · Security For Everyone.*
