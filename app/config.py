from __future__ import annotations

import os

from dotenv import load_dotenv

load_dotenv()


LLM_BASE_URL: str = os.getenv("LLM_BASE_URL", "http://localhost:11434/v1")
LLM_MODEL: str = os.getenv("LLM_MODEL", "llama3.2")
LLM_API_KEY: str = os.getenv("LLM_API_KEY", "ollama")
DATABASE_URL: str = os.getenv(
    "DATABASE_URL", "postgresql://pentest:pentest@localhost:5432/pentest"
)
NVD_API_URL: str = os.getenv(
    "NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

# Phase 2 settings
SCORING_FORMULA: str = os.getenv("SCORING_FORMULA", "phase2").lower()
APP_API_KEY: str = os.getenv("APP_API_KEY", "")
