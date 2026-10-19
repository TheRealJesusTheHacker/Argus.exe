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

**Phase 4 complete (v0.5.0) — quarantine, actions & reporting are live.** What Argus catches can now be *handled*, under the rule the whole product is built on: **nothing happens to your files behind your back**. Malicious files from a scan can be quarantined or deleted (your flags, or an interactive prompt) into an **encrypted quarantine vault** — streamed, authenticated, tamper-evident storage with opaque file names, where the encrypted copy is verified end-to-end *before* the original is ever removed, and a tampered vault copy refuses to restore. From the vault you can **restore** a file (never overwriting anything that took its place), **delete** it for good (through the vault, so the audit record survives), or **allow** it — restored, fingerprinted, and added to your exclusions so Argus leaves that exact file alone. Real-time protection routes its requests through a **pending-actions queue** by default (`argus pending list / approve / reject`): Argus asks, you decide. If you'd rather it act on the worst of the worst, the `realtime_default` policy can auto-quarantine Critical findings — but **deletion is never automatic, under any setting**. Every scan and detection is written into a persistent **history** with plain-language reasons and outcomes, rendered by `argus report` and `argus history`. What remains is honest and unchanged: the process monitor scans a program *as* it starts (pre-execution blocking arrives with the Phase 5 service/driver work), and the vault's encryption is there to neutralize threats, not to store secrets. Next: Phase 5 — the premium GUI, Dev Toolkit, and the install that makes Argus the machine's default security app.

## The family

Argus is a Sentinel Safeguard product, alongside **Hellhound.exe** (malware education — see what real malware does, safely announced) and **J.A.D.E.** (local AI assistant). Argus is the shield to Hellhound's lesson: one shows you the threat, the other stops it.

---

*Sentinel Safeguard LLC — Kansas City, MO · Security For Everyone.*
