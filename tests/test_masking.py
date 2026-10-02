from src.agent.masking.secrets_masker import redact_secrets

def test_ip_redaction():
    code = "server_ip = '192.168.1.100'"
    masked = redact_secrets(code)
    assert "[REDACTED_IP]" in masked
    assert "192.168.1.100" not in masked

def test_secret_redaction():
    code = "api_key = 'sk_live_123456789'"
    masked = redact_secrets(code)
    assert "[REDACTED_SECRET]" in masked
    assert "sk_live_123456789" not in masked

def test_mixed_redaction():
    code = "db_password = 'super_secret'\nhost = '10.0.0.1'"
    masked = redact_secrets(code)
    assert "[REDACTED_SECRET]" in masked
    assert "[REDACTED_IP]" in masked
    assert "super_secret" not in masked
    assert "10.0.0.1" not in masked
