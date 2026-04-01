"""
eval_config.py  –  Evaluation framework configuration.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# ── Root paths ───────────────────────────────────────────────────────────────
EVAL_DIR     = Path(__file__).resolve().parent          
PROJECT_ROOT = EVAL_DIR.parent                          
BOT_DIR      = PROJECT_ROOT / "Bot"                     

# ── Ghidra ───────────────────────────────────────────────────────────────────
GHIDRA_PATH = os.environ.get(
    "GHIDRA_PATH",
    str(PROJECT_ROOT / "ghidra_12.0.1_PUBLIC/support/analyzeHeadless"),
)

# ── Compiler flags ───────────────────────────────────────────────────────────
COMPILE_FLAGS_DEBUG    = ["-g", "-O0", "-no-pie"]
COMPILE_FLAGS_STRIPPED = ["-O0", "-no-pie"]   

# ── Workspace dirs (created fresh per evaluation run) ────────────────────────
EVAL_WORKSPACE  = EVAL_DIR / "workspace"
DEBUG_BIN_NAME  = "target_debug"
STRIP_BIN_NAME  = "target_stripped"

# ── Scoring thresholds & Settings ─────────────────────────────────────────────
# FIXED: Lowered threshold to catch common reverse engineering abbreviations
FUZZY_MATCH_THRESHOLD = 0.45   

# FIXED: Enable LLM as a judge for semantic similarity
USE_LLM_JUDGE = True

# ── Report ────────────────────────────────────────────────────────────────────
REPORT_JSON = EVAL_DIR / "eval_report.json"
REPORT_HTML = EVAL_DIR / "eval_report.html"