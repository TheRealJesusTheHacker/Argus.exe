# Hash-verified installs (`--require-hashes`)

Fleet policy (owner, adopted 2026-10-25): **every dependency install —
local, build, CI — verifies hashes against a committed lock generated
from a known-good resolution, and fails loudly on any mismatch.** A
version bump is not landed until its hashes are locked. Exceptions
exist only as documented entries with evidence (bottom of this file).

The human-edited pin files stay the source of truth for *versions*;
each has a sibling *lock* that carries the full resolved set (direct +
transitive) with a `sha256` hash for every artifact:

| Source input | Lock | Install command |
|---|---|---|
| `packaging/requirements-ci.txt` (Windows) | `packaging/requirements-ci.lock.txt` | `pip install --require-hashes -r packaging/requirements-ci.lock.txt` |
| `packaging/requirements-ci-linux.txt` (Linux) | `packaging/requirements-ci-linux.lock.txt` | `pip install --require-hashes -r packaging/requirements-ci-linux.lock.txt` |

The package itself is then installed against the verified set with
build isolation off, so its build backend is the hash-verified
setuptools from the lock (see EX-A1):

```bash
pip install --no-deps --no-build-isolation ".[gui,windows]"   # Windows
pip install --no-deps --no-build-isolation ".[gui]"            # Linux
```

Every install path in this repo uses the locks: the `build-release`
workflow (both jobs), `packaging/linux/build-deb.sh`'s instructions,
and the README's from-source and development instructions.

## How the locks were generated (2026-10-25)

* **Linux lock** — `pip-compile --generate-hashes --allow-unsafe`
  (pip-tools 7.6.2, CPython 3.12, Linux) from
  `packaging/requirements-ci-linux.txt`. Every direct pin kept its
  exact version; transitives resolved to iniconfig 2.3.1, pluggy
  1.7.0, Pygments 2.21.0, shiboken6 6.12.0 and the PySide6 sub-packages
  — identical to a plain install of the pin file on the same day.
  Hashes cover every artifact the index publishes per version.
* **Windows lock** — pip-compile cannot resolve this set on Linux
  (pywin32 publishes no Linux distribution), so the set was resolved
  by pip itself against the wired CI target and every artifact hashed
  from the download (`pip hash` equivalent):

  ```bash
  pip download -r packaging/requirements-ci.txt \
      --platform win_amd64 --python-version 312 --implementation cp \
      --abi cp312 --abi abi3 --abi none --only-binary=:all:
  ```

  The hashes are therefore the win_amd64 / CPython 3.12 artifacts —
  exactly what the Windows release job (windows-latest, Python 3.12)
  installs. One entry no Linux-side download can produce, `colorama`
  (pytest's win32-only dependency; pip's `--platform` download does
  not evaluate that marker from a Linux host), carries every artifact
  hash the index publishes for colorama 0.4.6 — the version a Windows
  resolver picks today for `colorama>=0.4` — cross-checked against
  the downloaded wheel.

## Regenerating after a deliberate bump

1. Edit the pin in `packaging/requirements-ci*.txt` (and in
   `pyproject.toml`'s build-system if it is setuptools).
2. Regenerate the Linux lock with the pip-compile command above.
3. Regenerate the Windows lock with the download-and-hash route
   above, and re-add the colorama entry the same way.
4. Re-run the acceptance checks below before landing: a clean-venv
   `--require-hashes` install of each lock, the full suite, and a
   one-character tamper test that must fail.

## Verification record (2026-10-25, this rollout)

* Clean venv, Linux: `pip install --require-hashes -r
  packaging/requirements-ci-linux.lock.txt` — success, 15 packages.
  Followed by `pip install --no-deps --no-build-isolation ".[gui]"` —
  success (argus-exe 1.2.12 built by the lock's setuptools 84.1.0).
* Windows target: `pip download --require-hashes` with the
  win_amd64 / CPython 3.12 target flags — success, all 18 platform
  artifacts hash-verified. (From a Linux host, pip skips the
  win32-marked colorama entry; on Windows it is verified against the
  listed hashes like everything else.)
* Test suite: **827 passed, 1 skipped** before and after this change
  (Linux GUI venv, `QT_QPA_PLATFORM=offscreen`) — unchanged.
* Tamper tests (scratch copies, one hex character corrupted,
  `--no-cache-dir`): corrupting the shiboken6 wheel hash in the Linux
  lock and the pywin32 hash in the Windows lock each made the install
  fail with pip's `THESE PACKAGES DO NOT MATCH THE HASHES FROM THE
  REQUIREMENTS FILE` error, showing the corrupted expected hash
  against the genuine artifact hash. Note: the corrupted package must
  be one with no second usable artifact — corrupting only the *wheel*
  hash of a package that also publishes an sdist makes pip fall back
  to the (still hash-verified) sdist instead of failing, which is why
  wheel-only shiboken6 and pywin32 were used.

## Exceptions

* **EX-A1 — build-system isolation on manual installs.** `pyproject.toml`
  pins the build backend exactly (`setuptools==84.1.0`), but under
  pip's default build isolation that backend is fetched from the
  index without hash verification — pip offers no way to hash-check
  PEP 518 build requirements. *Mitigation wired everywhere this
  project controls the install:* setuptools 84.1.0 is in both locks,
  and every workflow/README install of the package itself uses
  `--no-build-isolation`, so the backend used is the hash-verified
  copy. The residual exception is a user running a bare
  `pip install .` with isolation on: the backend version is still
  the exact pin, verified only by the index connection itself.
* **EX-A2 — pyproject runtime extras are minimums.**
  `[project.optional-dependencies]` declares `PySide6>=6.6` and
  `pywin32>=306` for end users installing from source; a repository
  lock file cannot travel with a package install, so that
  convenience path is not hash-verified. Bounded because (a) the
  engine's runtime is pure standard library — the extras are the
  optional GUI and Windows-service layers; (b) the exact artifacts
  those minimums resolve to in this project's own builds
  (PySide6 6.12.0 and its closure, pywin32 312) are hash-locked in
  both CI locks; (c) every project-controlled install path uses the
  locks.

Out of scope, by mechanism rather than exception: the workflow's
`apt-get` Qt runtime libraries are distribution packages, verified by
the Debian/Ubuntu archive signatures apt itself enforces — a
different, platform-native verification, not a PyPI hash.
