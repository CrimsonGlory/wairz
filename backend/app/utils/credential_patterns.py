"""Shared credential and secrets detection patterns.

Used by both the MCP `find_hardcoded_credentials` tool (ai/tools/strings.py)
and the automated security audit service (services/security_audit/credentials.py).

Patterns sourced from:
- Custom firmware-specific patterns
- Gitleaks (MIT licensed) — cloud service API key patterns
- Industry CVE/CWE references
"""

import re

# ---------------------------------------------------------------------------
# Generic credential patterns (key=value style)
# ---------------------------------------------------------------------------

# The leading `\w*` lets the suffix match prefixed config keys like
# IOT_APP_KEY, WYZE_OTA_UPDATE_KEY, CLIENT_SECRET, ACCESS_TOKEN — vendors
# rarely name their credential fields verbatim "password" or "api_key".
# The leading `\b` keeps the prefix from starting mid-word.
CREDENTIAL_PATTERNS = [
    re.compile(r"\b\w*(?:password|passwd|pwd)\s*[=:]\s*(\S+)", re.IGNORECASE),
    re.compile(r"\b\w*secret\s*[=:]\s*(\S+)", re.IGNORECASE),
    re.compile(r"\b\w*token\s*[=:]\s*(\S+)", re.IGNORECASE),
    re.compile(r"\b\w*credential\s*[=:]\s*(\S+)", re.IGNORECASE),
    re.compile(r"\b\w*api[_-]?key\s*[=:]\s*(\S+)", re.IGNORECASE),
    re.compile(r"\b\w*app[_-]?key\s*[=:]\s*(\S+)", re.IGNORECASE),
    # Catch-all *_key= for vendor-specific naming. The underscore-or-dash
    # prefix avoids matching keyboard=, monkey=, etc.
    re.compile(r"\b\w+[_-]key\s*[=:]\s*(\S+)", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# High-confidence API key and secrets patterns
# Each tuple: (compiled_regex, category_name, severity)
# ---------------------------------------------------------------------------

API_KEY_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # ── AWS ──
    (re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])"), "aws_access_key", "critical"),
    (re.compile(r"(?:aws_secret_access_key|secret_access_key)\s*[=:]\s*([A-Za-z0-9/+=]{40})"), "aws_secret_key", "critical"),

    # ── Azure ──
    (re.compile(r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+"), "azure_connection_string", "critical"),
    (re.compile(r"sv=\d{4}-\d{2}-\d{2}.*sig=[A-Za-z0-9%+/=]{43,}"), "azure_sas_token", "high"),

    # ── GCP ──
    (re.compile(r"AIza[0-9A-Za-z_-]{35}"), "gcp_api_key", "high"),
    (re.compile(r'"type"\s*:\s*"service_account"'), "gcp_service_account", "critical"),

    # ── GitHub ──
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "github_pat", "critical"),
    (re.compile(r"gho_[A-Za-z0-9]{36}"), "github_oauth", "critical"),
    (re.compile(r"ghs_[A-Za-z0-9]{36}"), "github_app_token", "high"),
    (re.compile(r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}"), "github_fine_grained_pat", "critical"),

    # ── GitLab ──
    (re.compile(r"glpat-[A-Za-z0-9_-]{20}"), "gitlab_pat", "critical"),
    (re.compile(r"glptt-[a-f0-9]{40}"), "gitlab_pipeline_trigger", "high"),

    # ── Stripe ──
    (re.compile(r"sk_live_[A-Za-z0-9]{24,}"), "stripe_secret_key", "critical"),
    (re.compile(r"pk_live_[A-Za-z0-9]{24,}"), "stripe_publishable_key", "medium"),
    (re.compile(r"[sp]k_test_[A-Za-z0-9]{24,}"), "stripe_test_key", "low"),
    (re.compile(r"rk_live_[A-Za-z0-9]{24,}"), "stripe_restricted_key", "critical"),

    # ── Slack ──
    (re.compile(r"xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24}"), "slack_bot_token", "critical"),
    (re.compile(r"xoxp-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[a-f0-9]{32}"), "slack_user_token", "critical"),
    (re.compile(r"xoxa-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9-]+"), "slack_app_token", "critical"),
    (re.compile(r"xoxr-[0-9]{10,}-[A-Za-z0-9-]+"), "slack_config_token", "critical"),
    (re.compile(r"hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}"), "slack_webhook", "high"),

    # ── JWT ──
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"), "jwt_token", "high"),

    # ── Twilio ──
    (re.compile(r"AC[a-f0-9]{32}"), "twilio_account_sid", "medium"),
    (re.compile(r"SK[a-f0-9]{32}"), "twilio_api_key", "high"),

    # ── SendGrid ──
    (re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"), "sendgrid_api_key", "critical"),

    # ── Mailgun ──
    (re.compile(r"key-[a-f0-9]{32}"), "mailgun_api_key", "high"),

    # ── Mailchimp ──
    (re.compile(r"[a-f0-9]{32}-us[0-9]{1,2}"), "mailchimp_api_key", "high"),

    # ── Square / Block ──
    (re.compile(r"sq0atp-[A-Za-z0-9_-]{22}"), "square_access_token", "critical"),
    (re.compile(r"sq0csp-[A-Za-z0-9_-]{43}"), "square_oauth_secret", "critical"),

    # ── Shopify ──
    (re.compile(r"shpat_[a-fA-F0-9]{32}"), "shopify_access_token", "critical"),
    (re.compile(r"shpss_[a-fA-F0-9]{32}"), "shopify_shared_secret", "critical"),

    # ── Heroku ──
    (re.compile(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"), "heroku_api_key", "low"),
    # ^ UUID pattern — low severity, many false positives

    # ── Datadog ──
    (re.compile(r"[a-f0-9]{32}(?=.*datadog)", re.IGNORECASE), "datadog_api_key", "high"),

    # ── DigitalOcean ──
    (re.compile(r"dop_v1_[a-f0-9]{64}"), "digitalocean_pat", "critical"),
    (re.compile(r"doo_v1_[a-f0-9]{64}"), "digitalocean_oauth", "critical"),

    # ── Telegram ──
    (re.compile(r"[0-9]{8,10}:[A-Za-z0-9_-]{35}"), "telegram_bot_token", "high"),

    # ── Discord ──
    (re.compile(r"[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}"), "discord_bot_token", "critical"),

    # ── Firebase ──
    (re.compile(r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"), "firebase_cloud_messaging", "high"),

    # ── npm ──
    (re.compile(r"npm_[A-Za-z0-9]{36}"), "npm_access_token", "critical"),

    # ── PyPI ──
    (re.compile(r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}"), "pypi_upload_token", "critical"),

    # ── Hashicorp Vault ──
    (re.compile(r"hvs\.[A-Za-z0-9_-]{24,}"), "hashicorp_vault_service_token", "critical"),
    (re.compile(r"hvb\.[A-Za-z0-9_-]{24,}"), "hashicorp_vault_batch_token", "critical"),

    # ── Doppler ──
    (re.compile(r"dp\.st\.[A-Za-z0-9_-]{43,}"), "doppler_service_token", "critical"),

    # ── Grafana ──
    (re.compile(r"glc_[A-Za-z0-9_-]{32,}"), "grafana_cloud_api_key", "high"),
    (re.compile(r"glsa_[A-Za-z0-9_-]{32}_[a-f0-9]{8}"), "grafana_service_account", "high"),

    # ── Postman ──
    (re.compile(r"PMAK-[A-Za-z0-9]{24}-[A-Za-z0-9]{34}"), "postman_api_key", "high"),

    # ── Supabase ──
    (re.compile(r"sbp_[a-f0-9]{40}"), "supabase_service_key", "critical"),

    # ── Linear ──
    (re.compile(r"lin_api_[A-Za-z0-9]{40}"), "linear_api_key", "high"),

    # ── OpenAI ──
    (re.compile(r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}"), "openai_api_key", "critical"),
    (re.compile(r"sk-proj-[A-Za-z0-9_-]{40,}"), "openai_project_key", "critical"),

    # ── Anthropic ──
    (re.compile(r"sk-ant-api03-[A-Za-z0-9_-]{93}"), "anthropic_api_key", "critical"),

    # ── OTP/2FA seeds ──
    (re.compile(r"otpauth://[ht]otp/[^\s]+\?secret=[A-Z2-7]+=*"), "otp_auth_uri", "critical"),

    # ── Connection strings (database) ──
    (re.compile(r"(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis|amqp)://[^\s:]+:[^\s@]+@[^\s]+"), "database_connection_string", "critical"),

    # ── Generic high-entropy hex secrets (32+ chars in key= context) ──
    (re.compile(r"(?:secret|private|auth)[-_]?key\s*[=:]\s*[a-f0-9]{32,}", re.IGNORECASE), "generic_hex_secret", "high"),
]

# ---------------------------------------------------------------------------
# Hash type identification for /etc/shadow analysis
# ---------------------------------------------------------------------------

HASH_TYPES = {
    "$1$": ("MD5", "weak"),
    "$2a$": ("Blowfish", "ok"),
    "$2b$": ("Blowfish", "ok"),
    "$5$": ("SHA-256", "ok"),
    "$6$": ("SHA-512", "ok"),
    "$y$": ("yescrypt", "ok"),
}
