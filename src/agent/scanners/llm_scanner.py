import json

from google import genai
from pydantic import ValidationError

from src.agent.config import GEMINI_API_KEY, MODEL_NAME
from src.agent.masking.secrets_masker import redact_secrets
from src.agent.schemas import Finding


def scan_function(function_code: str) -> Finding | None:
    """
    Scans a Python function for security vulnerabilities using Gemini.
    Returns a structured Finding object if a vulnerability is detected.
    """
    if not GEMINI_API_KEY:
        raise ValueError("GEMINI_API_KEY is not configured")

    # Mask secrets before sending to LLM
    safe_code = redact_secrets(function_code)
    
    client = genai.Client(api_key=GEMINI_API_KEY)
    
    prompt = f"""
    You are an expert DevSecOps auditor. Review the following Python function for security vulnerabilities.
    Specifically look for SQL injection, Command injection, and Hardcoded secrets.
    
    If you find a vulnerability, report it using the provided JSON schema. 
    If the function is secure, return an empty JSON object {{}}.
    
    CRITICAL: For the `suggested_fix` field, you MUST return ONLY the raw, complete, and patched Python code. Do NOT include any explanations, markdown formatting, or conversational text in the `suggested_fix` field.
    CRITICAL: You MUST preserve all proper Python indentation and newlines in the `suggested_fix` string. Do not compress the code into a single line.
    
    Code to analyze:
    ```python
    {safe_code}
    ```
    """
    
    try:
        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=prompt,
            config={
                'response_mime_type': 'application/json',
                'response_schema': Finding,
                'temperature': 0.0,
            }
        )
        if response.text and response.text.strip() != "{}":
            data = json.loads(response.text)
            return Finding(**data)
        return None
    except ValidationError as e:
        print(f"Validation error in LLM response: {e}")
        return None
    except Exception as e:
        print(f"LLM Scan error: {e}")
        return None
