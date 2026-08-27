"""Shared pytest fixtures — ensures the synthetic samples exist before tests run."""

import os
import subprocess
import sys

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "samples")
# eicar.com is intentionally absent — it is served in-memory by main.py and
# never written to disk (the host's antivirus would quarantine it).
REQUIRED = {"benign.exe", "packed.exe", "suspicious_imports.exe"}


def pytest_configure(config):
    existing = set(os.listdir(SAMPLES_DIR)) if os.path.isdir(SAMPLES_DIR) else set()
    if not REQUIRED.issubset(existing):
        subprocess.run(
            [sys.executable, os.path.join(SAMPLES_DIR, "generate_samples.py")],
            check=True,
        )
