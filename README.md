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

**Phase 3 complete (v0.4.0) — real-time protection is live.** Argus now watches the folders threats land in (Downloads, Desktop, Documents, temp) and scans every file the moment it finishes being written — a debounce waits until a download stops changing before judging it, so nothing is scanned half-written. A process monitor notices programs starting and scans the file each one launched from. Every detection is answered by a per-severity response policy (Critical/High → quarantine request, Medium → alert, Low → log), configured in a plain JSON file whose exclusions — by path and by fingerprint — are honoured in real-time *and* on-demand scans. It all runs in a service-ready core (`argus watch`, with a JSON heartbeat you can check via `argus watch-status`) that shuts down cleanly and is built to graduate into the boot-start Windows service in Phase 5. Two honest limits, stated plainly: the process monitor scans a program *as* it starts — stopping one *before* it runs arrives with the service/driver phase — and Phase 3 only *reports* actions; moving files into quarantine is Phase 4, always with your say-so. Next: Phase 4 quarantine, actions & reporting.

## The family

Argus is a Sentinel Safeguard product, alongside **Hellhound.exe** (malware education — see what real malware does, safely announced) and **J.A.D.E.** (local AI assistant). Argus is the shield to Hellhound's lesson: one shows you the threat, the other stops it.

---

*Sentinel Safeguard LLC — Kansas City, MO · Security For Everyone.*
