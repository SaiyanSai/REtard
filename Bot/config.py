import os
from dotenv import load_dotenv
from google import genai

# Load environment variables
load_dotenv()

# --- FILE PATHS ---
STATE_FILE = "Bot/analysis_state.json"
CHECKPOINT_DB = "Bot/graph_checkpoint.db"
TRIAGE_CACHE = "Bot/triage_cache.json"
STRINGS_JSON = "Bot/function_strings.json"
OUTPUT_C = "Bot/decompiled_output.c"
TARGET_BINARY = os.getenv("TARGET_BINARY", "spider.exe")

# --- LLM SETUP ---
API_KEY = os.getenv("GEMINI_API_KEY")
# Standard client initialization
client = genai.Client(api_key=API_KEY) if API_KEY else None