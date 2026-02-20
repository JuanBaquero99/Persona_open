"""
Tests for Domain Filtering — data exfiltration prevention.

Simulates attacks where the agent tries to send data to:
  - Paste services (pastebin.com)
  - Webhook catchers (webhook.site)
  - Tunneling services (ngrok.io)
  - URL shorteners (bit.ly)
  - Raw IP addresses
  - Private IPs (lateral movement)
"""

import pytest
from secureagent.domain import DomainFilterRule, DomainScanResult
from secureagent.proxy import SecureProxy, SecurityException


@pytest.fixture
def domain_filter():
    return DomainFilterRule()


@pytest.fixture
def strict_domain_filter():
    return DomainFilterRule(
        allowed_domains={"api.company.com", "docs.google.com"},
        block_all_ips=True,
    )


# ─────────────────────────────────────────────
#  Paste services
# ─────────────────────────────────────────────

class TestPasteServices:

    def test_blocks_pastebin(self, domain_filter):
        result = domain_filter.scan("I'll upload the data to https://pastebin.com/raw/abc123")
        assert not result.is_clean
        assert len(result.blocked_urls) > 0

    def test_blocks_hastebin(self, domain_filter):
        result = domain_filter.scan("See https://hastebin.com/share/xyz")
        assert not result.is_clean

    def test_blocks_paste_ee(self, domain_filter):
        result = domain_filter.scan("Results at https://paste.ee/p/abc")
        assert not result.is_clean


# ─────────────────────────────────────────────
#  Webhook / request catchers
# ─────────────────────────────────────────────

class TestWebhookCatchers:

    def test_blocks_webhook_site(self, domain_filter):
        result = domain_filter.scan("Sending to https://webhook.site/abc-123-def")
        assert not result.is_clean
        assert result.blocked_urls[0]["domain"] == "webhook.site"

    def test_blocks_requestbin(self, domain_filter):
        result = domain_filter.scan("POST to https://requestbin.com/r/abc123")
        assert not result.is_clean

    def test_blocks_pipedream(self, domain_filter):
        result = domain_filter.scan("Forward to https://pipedream.com/workflows/abc")
        assert not result.is_clean


# ─────────────────────────────────────────────
#  Tunneling services
# ─────────────────────────────────────────────

class TestTunnelingServices:

    def test_blocks_ngrok(self, domain_filter):
        result = domain_filter.scan("Connect to https://abc123.ngrok.io/api")
        assert not result.is_clean

    def test_blocks_ngrok_free_app(self, domain_filter):
        result = domain_filter.scan("https://something.ngrok-free.app/collect")
        assert not result.is_clean

    def test_blocks_localtunnel(self, domain_filter):
        result = domain_filter.scan("Use https://my-app.localtunnel.me")
        assert not result.is_clean


# ─────────────────────────────────────────────
#  URL shorteners
# ─────────────────────────────────────────────

class TestURLShorteners:

    def test_blocks_bitly(self, domain_filter):
        result = domain_filter.scan("Click https://bit.ly/3abc123")
        assert not result.is_clean

    def test_blocks_tinyurl(self, domain_filter):
        result = domain_filter.scan("See https://tinyurl.com/y7abc123")
        assert not result.is_clean


# ─────────────────────────────────────────────
#  IP-based URLs
# ─────────────────────────────────────────────

class TestIPBasedURLs:

    def test_blocks_private_ip_by_default(self, domain_filter):
        result = domain_filter.scan("Send to http://192.168.1.100:8080/collect")
        assert not result.is_clean
        assert len(result.suspicious_ips) > 0

    def test_blocks_10_range_private_ip(self, domain_filter):
        result = domain_filter.scan("Connect to http://10.0.0.5:3000/api")
        assert not result.is_clean

    def test_blocks_172_range_private_ip(self, domain_filter):
        result = domain_filter.scan("Upload to http://172.16.0.1/upload")
        assert not result.is_clean

    def test_blocks_all_ips_in_strict_mode(self, strict_domain_filter):
        result = strict_domain_filter.scan("Results at http://8.8.8.8/data")
        assert not result.is_clean


# ─────────────────────────────────────────────
#  Whitelist mode
# ─────────────────────────────────────────────

class TestWhitelistMode:

    def test_allows_whitelisted_domain(self, strict_domain_filter):
        result = strict_domain_filter.scan("Fetching from https://api.company.com/data")
        assert result.is_clean

    def test_blocks_non_whitelisted_domain(self, strict_domain_filter):
        result = strict_domain_filter.scan("Fetching from https://random-site.com/data")
        assert not result.is_clean

    def test_allows_subdomain_of_whitelisted(self, strict_domain_filter):
        result = strict_domain_filter.scan("See https://v2.api.company.com/data")
        assert result.is_clean


# ─────────────────────────────────────────────
#  Clean output — NO false positives
# ─────────────────────────────────────────────

class TestCleanOutput:

    def test_normal_text_passes(self, domain_filter):
        result = domain_filter.scan("The quarterly revenue was $10M, up 15% from last year.")
        assert result.is_clean

    def test_safe_urls_pass(self, domain_filter):
        result = domain_filter.scan("Visit our website at https://www.company.com for more info")
        assert result.is_clean

    def test_google_passes(self, domain_filter):
        result = domain_filter.scan("Search on https://www.google.com for answers")
        assert result.is_clean

    def test_github_passes(self, domain_filter):
        result = domain_filter.scan("Code is at https://github.com/myorg/myrepo")
        assert result.is_clean

    def test_empty_text_passes(self, domain_filter):
        result = domain_filter.scan("")
        assert result.is_clean


# ─────────────────────────────────────────────
#  Sanitization
# ─────────────────────────────────────────────

class TestDomainSanitization:

    def test_redacts_blocked_url(self, domain_filter):
        text = "Upload results to https://pastebin.com/raw/abc123 for sharing"
        sanitized = domain_filter.sanitize(text)
        assert "pastebin.com" not in sanitized or "BLOCKED_URL" in sanitized

    def test_redacts_webhook_url(self, domain_filter):
        text = "Sending data to https://webhook.site/abc-123"
        sanitized = domain_filter.sanitize(text)
        assert "BLOCKED_URL" in sanitized

    def test_preserves_safe_text(self, domain_filter):
        text = "The revenue was $10M last quarter."
        sanitized = domain_filter.sanitize(text)
        assert sanitized == text


# ─────────────────────────────────────────────
#  Metadata
# ─────────────────────────────────────────────

class TestDomainMetadata:

    def test_blocked_url_has_reason(self, domain_filter):
        result = domain_filter.scan("https://pastebin.com/raw/abc")
        assert "reason" in result.blocked_urls[0]

    def test_blocked_url_has_domain(self, domain_filter):
        result = domain_filter.scan("https://webhook.site/abc")
        assert result.blocked_urls[0]["domain"] == "webhook.site"

    def test_total_threats_count(self, domain_filter):
        text = "Upload to https://pastebin.com/abc and https://webhook.site/def"
        result = domain_filter.scan(text)
        assert result.total_threats >= 2


# ─────────────────────────────────────────────
#  SecureProxy integration — E2E
# ─────────────────────────────────────────────

class TestProxyDomainIntegration:

    def test_proxy_redacts_exfiltration_url_in_output(self):
        class ExfilAgent:
            def run(self, p):
                return "I've uploaded the data to https://pastebin.com/raw/abc123"

        proxy = SecureProxy(ExfilAgent())
        result = proxy.run("Upload the report")
        assert "BLOCKED_URL" in result

    def test_proxy_redacts_webhook_in_output(self):
        class WebhookAgent:
            def run(self, p):
                return "Sending results to https://webhook.site/my-hook"

        proxy = SecureProxy(WebhookAgent())
        result = proxy.run("Process the data")
        assert "BLOCKED_URL" in result

    def test_proxy_logs_exfiltration_event(self):
        class ExfilAgent:
            def run(self, p):
                return "Data sent to https://ngrok.io/collect?secret=abc"

        proxy = SecureProxy(ExfilAgent())
        proxy.run("Do the thing")

        blocked = proxy.get_blocked_events()
        exfil_events = [e for e in blocked if e["event_type"] == "data_exfiltration"]
        assert len(exfil_events) >= 1

    def test_proxy_allows_safe_output_urls(self):
        class SafeAgent:
            def run(self, p):
                return "Find docs at https://docs.python.org/3/library/"

        proxy = SecureProxy(SafeAgent())
        result = proxy.run("Where are the Python docs?")
        assert "docs.python.org" in result
        assert "BLOCKED" not in result
