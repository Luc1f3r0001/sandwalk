# Sandwalk

![Platform](https://img.shields.io/badge/platform-macOS-black)
![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)
![Version](https://img.shields.io/badge/version-1.3.8-blue)
![License](https://img.shields.io/badge/license-Apache%202.0-green)

**Sandwalk** is a continuous **endpoint secrets scanner** for macOS developer fleets. It runs as a single Go binary on every Mac, finds leaked credentials, **validates them live** against their provider, and reports only **confirmed-active** ones to a self-hosted dashboard — without ever storing the plaintext.

## Why

Real credentials don't sit in git. They sit on developer laptops — `~/.aws/credentials`, an `.npmrc` token, a GitHub PAT in a shell profile. That's where attackers steal them, and it's the one place repo scanners and SIEMs never look.

Sandwalk watches that endpoint. Because it covers the whole fleet, it's also a **live map of your exposure**: which live secrets sit on which machine, right now. When a worm like **Shai-Hulud** rips through npm and harvests tokens off laptops, you intersect that map with your affected-machine list (from MDM, EDR, or a lockfile scan) and rotate the *exact* exposed set — instead of rotating the whole org blind.

> Sandwalk finds the *secrets*, not the malicious package. It answers "what live credentials were sitting there to be stolen, and where" — the half of incident response nobody else has.

## Key Features

- **Endpoint coverage** — one Go binary as a root LaunchDaemon on every Mac; no per-project setup.
- **Only live secrets** — every finding is validated against its provider. Dead and unverifiable matches are dropped, so the dashboard has zero noise.
- **17 detectors** — the credentials worms chase: npm, PyPI, GitHub, GitLab, AWS, GCP, Google, Stripe, Razorpay, OpenAI, Anthropic, DockerHub, SSH/TLS.
- **Three detection modes** — real-time FSEvents watcher, incremental daily sweep, and git-history walker.
- **Never stores your secrets** — the server holds only a value hash and a masked hint; validation runs on the device and returns only a verdict.

## How It Works

Sandwalk runs one engine ([MongoDB Kingfisher](https://github.com/mongodb/kingfisher)), scoped to the 17 detectors, fed by three sources:

1. **Real-time watcher** — FSEvents scans each file on create/modify/rename and uploads findings immediately.
2. **Incremental sweep** — a SQLite manifest (`path, size, ctime, inode, ruleset`) means the daily sweep re-scans only changed files.
3. **Git-history walker** — surfaces secrets that were committed and later deleted, with commit hash, author, and date.

**Validate-or-remove:** active → real credential; inactive → `rotated`; unvalidatable → silently dropped. The exception is **SSH/TLS keys** (no network validator): the owner's `~/.ssh` keys are kept and shown with passphrase status — a passphrase-less key is the dangerous case.

**Privacy:** the central store keeps only a hash and a masked hint. Every liveness check runs on the endpoint where the secret lives and returns only a verdict, so the server can't leak what it never holds.

## Architecture

![Sandwalk architecture](docs/architecture.png)

Findings flow **agent → API Gateway → SQS → Lambda → RDS → Sandwalk Server (ECS)** serving a React dashboard. Any live re-check is dispatched back to the device that holds the secret.

## Install

**Prerequisites:** macOS (Apple Silicon) + Xcode CLT, Go 1.26+, `brew install kingfisher`, and an MDM to push the `.pkg`.

```bash
git clone https://github.com/Luc1f3r0001/sandwalk.git
cd sandwalk
bash build.sh 1.3.8
```

This produces `releases/Sandwalk-1.3.8.pkg`. Push it to the target Mac device group via your MDM. Rollout details in [`setup/`](setup/).

## Credits

Sandwalk's detection and live-validation engine is **[MongoDB Kingfisher](https://github.com/mongodb/kingfisher)** (Rust, Hyperscan). Thanks to its maintainers and the wider open-source ecosystem Sandwalk is built on.

## License

[Apache License 2.0](LICENSE).
