"""
Kingfisher-backed credential validation for the dashboard.

The server shells out to the bundled `kingfisher validate` binary so the
"Check Active" and "Validate All" buttons use the exact same validation engine
as the endpoint agent. Returns True (active) / False (rotated) / None (unknown).
"""
import json
import os
import subprocess
from typing import Optional

KINGFISHER_BIN = os.getenv("KINGFISHER_BIN", "/usr/local/bin/kingfisher")

# our pattern_id → Kingfisher rule whose validator confirms a single value
VALIDATION_RULE = {
    "github_pat_classic":      "kingfisher.github.2",
    "github_pat_fine_grained": "kingfisher.github.1",
    "github_oauth_token":      "kingfisher.github.3",
    "gitlab_pat":              "kingfisher.gitlab.1",
    "stripe_live_secret":      "kingfisher.stripe.2",
    "razorpay_key_id":         "kingfisher.razorpay.1",
    "openai_key":              "kingfisher.openai.1",
    "anthropic_key":           "kingfisher.anthropic.1",
    "google_api_key":          "kingfisher.google.7",
    "npm_token":               "kingfisher.npm.1",
    "pypi_token":              "kingfisher.pypi.1",
    "aws_secret_access_key":   "kingfisher.aws.2",  # needs AKID via --var
}


def _validate_anthropic(key: str) -> Optional[bool]:
    """Authoritative Anthropic check (Kingfisher's bundled validator 404s on live
    keys). GET /v1/models is a read-only auth probe: 200=active, 401/403=invalid,
    anything else=inconclusive (never claim a live key is dead)."""
    import urllib.request
    import urllib.error
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/models",
        headers={"x-api-key": key, "anthropic-version": "2023-06-01"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status == 200
    except urllib.error.HTTPError as e:
        return False if e.code in (401, 403) else None
    except Exception:
        return None


def validate(pattern_id: str, value: str, aws_key_id: Optional[str] = None) -> Optional[bool]:
    """Validate a single secret value. Returns True/False/None."""
    if not value:
        return None
    # Custom validators override Kingfisher where its built-in validator is broken.
    if pattern_id == "anthropic_key":
        return _validate_anthropic(value)
    rule = VALIDATION_RULE.get(pattern_id)
    if not rule:
        return None

    cmd = [KINGFISHER_BIN, "validate", "--rule", rule, value, "--format", "json"]
    if pattern_id == "aws_secret_access_key":
        if not aws_key_id:
            return None
        cmd += ["--var", f"AKID={aws_key_id}"]

    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None

    raw = out.stdout.strip()
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None

    if data.get("status_code", 0) == 0:
        return None  # couldn't reach the API → unknown
    return bool(data.get("is_valid", False))
