import re

IP_REGEX = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
SECRET_REGEX = re.compile(r'(?i)(?:api_key|password|secret|token)[\s=:]+[\'"]([^\'"]+)[\'"]')

def redact_secrets(code: str) -> str:
    """
    Redacts potential secrets and IP addresses from the source code
    before it is sent to the LLM for analysis.
    """
    # Redact IPs
    masked_code = IP_REGEX.sub("[REDACTED_IP]", code)
    
    # Redact string literals that look like passwords/tokens
    def mask_match(match):
        full_match = match.group(0)
        secret_val = match.group(1)
        return full_match.replace(secret_val, "[REDACTED_SECRET]")
        
    masked_code = SECRET_REGEX.sub(mask_match, masked_code)
    
    return masked_code
