import os

from dotenv import load_dotenv

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

# Dynamic model selection configuration, avoiding hardcoded legacy versions
MODEL_NAME = os.getenv("MODEL_NAME", "gemini-2.5-pro")

# Thresholds
CONFIDENCE_THRESHOLD = 0.8
