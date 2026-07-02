# Sandwalk v1.2.0 — Kingfisher rewrite

A ground-up rewrite of the endpoint agent in **Go (single compiled binary)** with
**MongoDB Kingfisher** as the detection + validation engine, replacing the Python
agent + ripgrep + custom verifier.

## Why

The v1.1.x Python+ripgrep agent kept hanging on FIFOs/sockets/special files,
took 20+ minutes per full `/` scan, and re-scanned everything from scratch every
time. Kingfisher gates on `is_file()` before opening (FIFOs can never block it),
is Rust+Hyperscan fast, and validates inline.

## What changed

### Agent — now a single Go binary (`/opt/sandwalk/bin/sandwalk`)
- **Engine**: Kingfisher replaces ripgrep + `verifier.py`. Detection and live
  validation happen in one pass. Scoped to our 17 supply-chain detectors via
  `--rule`.
- **No more FIFO hang**: the Go walker `lstat`s and only ever hands regular files
  to Kingfisher; Kingfisher itself also gates on `is_file()`. The whole class of
  blocking bugs (and the 20-min watchdog) is gone.
- **Incremental scanning**: a SQLite manifest (`/var/db/sandwalk/manifest.sqlite`)
  tracks `path, size, ctime, inode`. The daily sweep only re-scans files whose
  `ctime`/`inode`/`size` changed. First sweep is a full baseline; thereafter only
  deltas. Ruleset changes invalidate the manifest and force a re-scan.
- **Real-time watcher**: macOS FSEvents → scan changed file → upload immediately.
- **Bundled binary**: `/opt/sandwalk/bin/kingfisher` ships in the `.pkg` (16 MB
  total, down from 143 MB).

### Finding lifecycle
- **Removed-but-active tag**: when a secret leaves a file, the agent re-validates
  the old value. If it's **rotated** → marked fixed. If it's **still live** (moved
  elsewhere) → new dashboard status **`removed_active`**.
- **Daily re-validation**: rotation is detected on a time cadence (not gated on
  file change), plus on demand via "Validate All".

### Dashboard + server
- **Validate All** button per machine → re-validates every active secret and pops
  up a summary (still-active vs rotated vs unknown).
- **Verification endpoints** now shell out to `kingfisher validate` (bundled in
  the ECS image) — same engine everywhere.
- **Multi-file locations** retained (a secret in several files shows all paths).
- New `removed_active` badge (purple) in the UI.

### Policy
Unchanged fetch/apply loop from API Gateway. Policy fields now map onto Kingfisher
flags: `patterns.enabled` → `--rule` allowlist, `exclude_paths` → walk skips,
`verify_credentials` → validation on/off, `ssh_require_no_passphrase` → drop
encrypted keys.

## Behavior changes to note
- **Standalone AWS AKIA key IDs are no longer reported on their own.** Kingfisher
  treats a key ID without its secret as non-exploitable and only surfaces the AWS
  **secret key** (auto-pairing the nearby key ID for STS validation). This is a
  deliberate precision improvement — a key ID alone can't be validated or used.
- **SSH/TLS keys**: passphrase-less keys are flagged (the dangerous case);
  encrypted keys are dropped when policy requires no-passphrase. Passphrase status
  is inferred from which Kingfisher rule fired.

## Distribution
Built via `bash build.sh 1.2.0` → `releases/Sandwalk-1.2.0.pkg`. **Not uploaded
to S3** — this is a standalone build for evaluation / fleet rollout.
