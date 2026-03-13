import os
from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()

# Update this path if your ghidra installation path is different
GHIDRA_PATH = "ghidra_12.0.1_PUBLIC/support/analyzeHeadless" 
PROJECT_DIR = "ghidra_projects"
PROJECT_NAME = "MyProject"
TARGET_BINARY = "cirno.dll"

OUTPUT_C = "Bot/decompiled_output.c"
STATE_FILE = "Bot/analysis_state.json"
CHECKPOINT_DB = "state.db" 

STRINGS_JSON = "Bot/function_strings.json"
TRIAGE_CACHE = "Bot/triage_cache.json"
GLOBAL_DATA_JSON = "Bot/global_data.json"

client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))