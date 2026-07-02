"""
Secret detection patterns — supply chain attack targets only.
Every pattern has: live verification, blast_radius, and remediation instructions.
"""
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Pattern:
    id: str
    name: str
    regex: str
    severity: str
    category: str
    description: str = ""
    verify_type: Optional[str] = None
    false_positives: list = field(default_factory=list)
    min_entropy: float = 0.0
    blast_radius: str = ""
    remediation: str = ""


PATTERNS: list[Pattern] = [

    # ── AWS ──────────────────────────────────────────────────────────────────────
    Pattern(
        id="aws_access_key_id",
        name="AWS Access Key ID",
        regex=r"\b(AKIA[A-Z0-9]{16})\b",
        severity="high", category="cloud",
        verify_type="aws_sts",
        false_positives=["AKIAIOSFODNN7EXAMPLE", "AKIAI44QH8DHBEXAMPLE"],
        min_entropy=3.0,
        blast_radius="Full programmatic AWS access — EC2, S3, RDS, IAM, Lambda. Attacker can exfiltrate data, spin up infra, or escalate via IAM.",
        remediation="1. AWS Console → IAM → Users → Security Credentials → Deactivate key.\n2. aws iam delete-access-key --access-key-id <KEY>\n3. Audit CloudTrail from key creation date.\n4. Create replacement key.",
    ),
    Pattern(
        id="aws_secret_access_key",
        name="AWS Secret Access Key",
        regex=r"(?i)(?:aws[_\-\.]?secret[_\-\.]?(?:access[_\-\.]?)?key)[\"'\s]*[=:][\"'\s]*([A-Za-z0-9/+]{40})",
        severity="critical", category="cloud",
        verify_type="aws_sts_secret",
        min_entropy=4.0,
        blast_radius="Full AWS API access when paired with key ID.",
        remediation="Rotate the key pair together via IAM console. Secret alone is useless without key ID.",
    ),
    Pattern(
        id="aws_session_token",
        name="AWS Session Token",
        regex=r"(?i)(?:aws[_\-\.]?session[_\-\.]?token)[\"'\s]*[=:][\"'\s]*([A-Za-z0-9/+=]{100,})",
        severity="high", category="cloud",
        verify_type="aws_sts_secret",
        blast_radius="Temporary STS credentials — same access as assumed IAM role. Expires ≤12h.",
        remediation="STS tokens expire automatically. Rotate the underlying long-lived credentials used to assume the role.",
    ),

    # ── GitHub ───────────────────────────────────────────────────────────────────
    Pattern(
        id="github_pat_classic",
        name="GitHub PAT (Classic)",
        regex=r"\b(ghp_[A-Za-z0-9]{36})\b",
        severity="high", category="vcs",
        verify_type="github",
        blast_radius="Read/write to all repos the user can access. Can be used to exfiltrate code, inject backdoors, or pivot to CI/CD.",
        remediation="github.com/settings/tokens → Delete token. Audit GitHub audit log for recent API usage.",
    ),
    Pattern(
        id="github_pat_fine_grained",
        name="GitHub PAT (Fine-Grained)",
        regex=r"\b(github_pat_[A-Za-z0-9_]{82})\b",
        severity="high", category="vcs",
        verify_type="github",
        blast_radius="Scoped to specific repos and permissions defined at token creation.",
        remediation="github.com/settings/tokens → Delete token.",
    ),
    Pattern(
        id="github_oauth_token",
        name="GitHub OAuth Token",
        regex=r"\b(gho_[A-Za-z0-9]{36})\b",
        severity="high", category="vcs",
        verify_type="github",
        blast_radius="OAuth app scopes — repo read/write, org access per app configuration.",
        remediation="github.com/settings/applications → Authorized OAuth Apps → Revoke.",
    ),

    # ── GitLab ───────────────────────────────────────────────────────────────────
    Pattern(
        id="gitlab_pat",
        name="GitLab Personal Access Token",
        regex=r"\b(glpat-[A-Za-z0-9_\-]{20})\b",
        severity="high", category="vcs",
        verify_type="gitlab",
        blast_radius="Read/write GitLab repos, CI/CD pipelines, container registry.",
        remediation="gitlab.com/-/profile/personal_access_tokens → Revoke token.",
    ),

    # ── Slack ────────────────────────────────────────────────────────────────────
    Pattern(
        id="slack_bot_token",
        name="Slack Bot Token",
        regex=r"\b(xox[baprs]-[0-9A-Za-z\-]{10,})\b",
        severity="high", category="saas",
        verify_type="slack",
        blast_radius="Read messages, post to channels, access workspace data per bot OAuth scopes.",
        remediation="api.slack.com/apps → Your App → OAuth & Permissions → Revoke All OAuth Tokens.",
    ),
    Pattern(
        id="slack_user_token",
        name="Slack User Token",
        regex=r"\b(xoxp-[0-9A-Za-z\-]{10,})\b",
        severity="high", category="saas",
        verify_type="slack",
        blast_radius="Full user-level Slack access — read DMs, post as user.",
        remediation="api.slack.com/apps → Revoke. Reset Slack password to invalidate all user tokens.",
    ),

    # ── Stripe ───────────────────────────────────────────────────────────────────
    Pattern(
        id="stripe_live_secret",
        name="Stripe Live Secret Key",
        regex=r"\b(sk_live_[A-Za-z0-9]{24,})\b",
        severity="critical", category="payment",
        verify_type="stripe",
        blast_radius="Full Stripe account — charge cards, issue refunds, read customer PII, create payouts to attacker bank.",
        remediation="dashboard.stripe.com → Developers → API Keys → Roll key immediately. Review API logs for unauthorized charges.",
    ),

    # ── Razorpay ─────────────────────────────────────────────────────────────────
    Pattern(
        id="razorpay_key_id",
        name="Razorpay Key ID",
        regex=r"\b(rzp_live_[A-Za-z0-9]{14})\b",
        severity="critical", category="payment",
        verify_type="razorpay",
        blast_radius="Live payment ops — create orders, capture payments, issue refunds, access customer data.",
        remediation="dashboard.razorpay.com → Settings → API Keys → Regenerate. Pair with new secret immediately.",
    ),

    # ── OpenAI ───────────────────────────────────────────────────────────────────
    Pattern(
        id="openai_key",
        name="OpenAI API Key",
        regex=r"\b(sk-(?:proj-)?[A-Za-z0-9_\-]{48,})\b",
        severity="high", category="ai",
        verify_type="openai",
        blast_radius="Billable OpenAI usage — GPT-4, DALL-E, Whisper. Attacker runs up charges or exfiltrates prompts.",
        remediation="platform.openai.com/api-keys → Delete key. Check usage dashboard for unexpected spend.",
    ),

    # ── Anthropic ────────────────────────────────────────────────────────────────
    Pattern(
        id="anthropic_key",
        name="Anthropic API Key",
        regex=r"\b(sk-ant-[A-Za-z0-9_\-]{90,})\b",
        severity="high", category="ai",
        verify_type="anthropic",
        blast_radius="Billable Anthropic API usage — Claude models.",
        remediation="console.anthropic.com → API Keys → Delete key.",
    ),

    # ── Google ───────────────────────────────────────────────────────────────────
    Pattern(
        id="google_api_key",
        name="Google API Key",
        regex=r"\b(AIza[A-Za-z0-9_\-]{35})\b",
        severity="high", category="cloud",
        verify_type="google",
        blast_radius="Access to enabled Google APIs (Maps, Gemini, YouTube, etc.) — may incur billing charges.",
        remediation="console.cloud.google.com → APIs & Services → Credentials → Delete key or add API/IP restrictions.",
    ),
    Pattern(
        id="gcp_service_account",
        name="GCP Service Account Key",
        regex=r'"private_key":\s*"(-----BEGIN [A-Z]+ PRIVATE KEY-----)',
        severity="critical", category="cloud",
        blast_radius="Full service account permissions — GCS, BigQuery, Compute Engine. Depends on IAM roles assigned.",
        remediation="console.cloud.google.com → IAM → Service Accounts → Keys → Delete key. Audit Cloud Audit Logs.",
    ),

    # ── Package registries (supply chain) ────────────────────────────────────────
    Pattern(
        id="npm_token",
        name="npm Auth Token",
        regex=r"(?://registry\.npmjs\.org/:_authToken=|npm_)([A-Za-z0-9_\-]{36,})",
        severity="high", category="supply_chain",
        verify_type="npm",
        blast_radius="Publish malicious packages to npm under your org — supply chain attack affecting all downstream users.",
        remediation="npmjs.com → Account → Access Tokens → Delete. Audit recent publishes for tampering.",
    ),
    Pattern(
        id="pypi_token",
        name="PyPI API Token",
        regex=r"\b(pypi-AgEI[A-Za-z0-9_\-]{100,})\b",
        severity="high", category="supply_chain",
        verify_type="pypi",
        blast_radius="Publish malicious packages to PyPI — supply chain attack.",
        remediation="pypi.org/manage/account/token/ → Remove token. Audit recent releases.",
    ),
    Pattern(
        id="dockerhub_pat",
        name="Docker Hub PAT",
        regex=r"\b(dckr_pat_[A-Za-z0-9_\-]{20,})\b",
        severity="high", category="supply_chain",
        verify_type="dockerhub",
        blast_radius="Push malicious images to Docker Hub — supply chain attack via container images pulled by CI/CD pipelines.",
        remediation="hub.docker.com/settings/security → Personal Access Tokens → Delete. Audit recent image pushes.",
    ),

    # ── Crypto keys ──────────────────────────────────────────────────────────────
    Pattern(
        id="ssh_private_key",
        name="SSH / TLS Private Key",
        regex=r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |ECDSA )?PRIVATE KEY-----)",
        severity="medium", category="crypto",
        blast_radius="SSH: access to any server the key is authorized on. TLS: decrypt traffic, impersonate the server.",
        remediation="1. Remove public key from all ~/.ssh/authorized_keys.\n2. Generate replacement: ssh-keygen -t ed25519\n3. If TLS: revoke cert at CA, reissue, redeploy.\n4. Audit server access logs from exposure date.",
    ),
]
