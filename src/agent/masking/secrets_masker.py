import logging
import re

logger = logging.getLogger(__name__)

# Patterns for various sensitive credentials and identifiers
IP_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
IPV6_REGEX = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b")
GENERIC_SECRET_REGEX = re.compile(
    r'(?i)(?:api_key|apikey|secret|password|passwd|token|auth_token|access_key)[\s=:]+[\'"]([^\'"]{4,})[\'"]'
)
AWS_KEY_REGEX = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
GITHUB_TOKEN_REGEX = re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{50,255})\b")
PRIVATE_KEY_REGEX = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
)


def redact_secrets(code: str) -> str:
    """
    Redacts potential secrets, API keys, tokens, private keys, and IP addresses
    from source code before it is passed to external LLM services or logs.
    """
    if not code:
        return ""

    # Redact private key blocks
    masked_code = PRIVATE_KEY_REGEX.sub("[REDACTED_PRIVATE_KEY]", code)

    # Redact IPv4 and IPv6
    masked_code = IP_REGEX.sub("[REDACTED_IP]", masked_code)
    masked_code = IPV6_REGEX.sub("[REDACTED_IP]", masked_code)

    # Redact specific known token formats
    masked_code = AWS_KEY_REGEX.sub("[REDACTED_AWS_KEY]", masked_code)
    masked_code = GITHUB_TOKEN_REGEX.sub("[REDACTED_GITHUB_TOKEN]", masked_code)

    # Redact generic credential assignments
    def mask_match(match: re.Match) -> str:
        full_match = match.group(0)
        secret_val = match.group(1)
        # Avoid redacting already redacted placeholders
        if "[REDACTED" in secret_val:
            return full_match
        return full_match.replace(secret_val, "[REDACTED_SECRET]")

    masked_code = GENERIC_SECRET_REGEX.sub(mask_match, masked_code)

    return masked_code


def mask_and_verify(code: str) -> tuple[str, bool, str]:
    """
    Masks code and verifies that dangerous unmasked secrets do not remain.
    Returns (redacted_code, is_safe, reason).
    """
    try:
        masked = redact_secrets(code)
        # Double check for unredacted private keys
        if "PRIVATE KEY-----" in masked and "[REDACTED_PRIVATE_KEY]" not in masked:
            return masked, False, "Unmasked private key fragment detected in source."
        return masked, True, "Redaction successful."
    except Exception as e:
        logger.error(f"Error during secret redaction: {e}")
        return code, False, f"Redaction failed due to error: {e}"

