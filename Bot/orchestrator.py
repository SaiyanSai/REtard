import json
import re
import os
import sys
from pathlib import Path
from google import genai
from httpx import Timeout
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# --- IMPORT EXISTING DECOMPILER ---
sys.path.append(str(Path(__file__).parent))
try:
    from decompile import decompile_binary
except ImportError:
    print("[!] Could not find Bot/decompile.py.")
    sys.exit(1)

# --- CONFIGURATION (Loaded from .env) ---
TARGET_BINARY = os.getenv("TARGET_BINARY", "/home/saiyansai/RE/spider.exe")
INPUT_C = str(Path(__file__).parent / "decompiled_output.c")
STATE_FILE = str(Path(__file__).parent / "analysis_state.json")
API_KEY = os.getenv("GEMINI_API_KEY")

if not API_KEY:
    print("[!] Error: GEMINI_API_KEY not found in .env file.")
    sys.exit(1)

client = genai.Client(api_key=API_KEY)

class REOrchestrator:
    def __init__(self, binary_path, output_c):
        self.binary_path = Path(binary_path)
        self.output_c = Path(output_c)
        self.state_file = Path(STATE_FILE)
        self.functions = {}
        self.symbol_table = {}

        if not self.output_c.exists():
            print(f"[*] Phase 1: Launching decompiler for {self.binary_path.name}...")
            decompile_binary(str(self.binary_path), str(self.output_c)) #
        
        if self.state_file.exists():
            self.load_state()
        else:
            self.initial_ingestion()

    def initial_ingestion(self):
        """Phase 2: Ingest and Identify."""
        print("[*] Phase 2: Ingesting functions...")
        with open(self.output_c, "r", encoding="utf-8") as f:
            content = f.read()

        # Capture ALL functions starting with FUN_ to prevent skipping
        pattern = r"// --- Function: (FUN_.*?) @ (.*?) ---\n(.*?)(?=\n// --- Function:|\Z)"
        matches = re.findall(pattern, content, re.DOTALL)

        for name, addr, body in matches:
            body_text = body.strip()
            self.functions[name] = {
                "address": addr,
                "body": body_text,
                "status": "PENDING",
                "proposed_name": name,
                "summary": "",
                "is_wrapper": self._check_if_wrapper(name, body_text),
                "string_score": -1,
                "revisit_reason": ""
            }
        print(f"[+] Ingested {len(self.functions)} functions.")
        self.save_state()

    def _check_if_wrapper(self, name, body):
        """Wrapper identification."""
        lines = [l.strip() for l in body.split('\n') if l.strip() and l not in ['{', '}'] and not l.startswith(('/', '*'))]
        if len(lines) > 12: return False
        calls = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', body)
        for target in calls:
            if not target.startswith("FUN_") and target not in ["if", "while", "for", "switch", "return"]:
                return True
        return False

    def _get_llm_string_score(self, body):
        """Initial bootstrap scoring."""
        strings = re.findall(r'"(.*?)"', body)
        clean = [s for s in strings if len(s) > 3]
        if not clean: return 0
        prompt = f"Rate these strings 0-10 for malware analysis relevance: {clean}. Return only integer."
        try:
            res = client.models.generate_content(model="gemini-2.0-flash", contents=prompt)
            return int(re.search(r'\d+', res.text).group())
        except: return 0

    def load_state(self):
        with open(self.state_file, "r") as f:
            data = json.load(f)
            self.functions = data["functions"]
            self.symbol_table = data["symbol_table"]

    def save_state(self):
        with open(self.state_file, "w") as f:
            json.dump({"functions": self.functions, "symbol_table": self.symbol_table}, f, indent=4)

    def llm_choose_next(self):
        """Phase 5 Logic: Let the LLM pick the next target."""
        summary = []
        for name, info in self.functions.items():
            if info["status"] in ["PENDING", "PARTIALLY_ANALYZED"]:
                summary.append({
                    "name": name,
                    "proposed": info["proposed_name"],
                    "status": info["status"],
                    "score": info["string_score"],
                    "summary": info["summary"][:100] + "..." if info["summary"] else "None",
                    "reason": info.get("revisit_reason", "")
                })

        if not summary: return None

        prompt = (
            "You are the orchestrator of an RE project. Below are pending/partially analyzed functions.\n"
            "Based on their summaries and string scores, pick the most critical function to analyze next.\n\n"
            f"STATE:\n{json.dumps(summary, indent=2)}\n\n"
            "Return: TARGET: [FUN_NAME] REASON: [Why this one?]"
        )
        
        try:
            res = client.models.generate_content(model="gemini-2.0-flash", contents=prompt)
            target_match = re.search(r"TARGET:\s*(FUN_[a-fA-F0-9]+)", res.text)
            return target_match.group(1) if target_match else summary[0]["name"]
        except:
            return summary[0]["name"]

    def analyze_function(self, target):
        print(f"[*] Analyzing: {target} (Status: {self.functions[target]['status']})")
        code = self.functions[target]['body']
        for old, new in self.symbol_table.items():
            code = re.sub(rf'\b{old}\b', new, code)

        prompt = (
            f"Analyze this function: {target}\n\nCode:\n{code}\n\n"
            "Return format:\nPROPOSED_NAME: [Name]\nSUMMARY: [Logic]\n"
            "STATUS: [ANALYZED or PARTIALLY_ANALYZED]\n"
            "REVISIT_REASON: [If partial, why?]"
        )

        try:
            res = client.models.generate_content(model="gemini-2.0-flash", contents=prompt)
            raw = res.text
            
            new_name = re.search(r"PROPOSED_NAME:\s*(.*)", raw).group(1).strip().replace("`", "")
            summary = re.search(r"SUMMARY:\s*(.*?)(?=STATUS:|$)", raw, re.DOTALL).group(1).strip()
            status = "ANALYZED"
            if "PARTIALLY_ANALYZED" in raw: status = "PARTIALLY_ANALYZED"
            reason = re.search(r"REVISIT_REASON:\s*(.*)", raw).group(1).strip() if "REVISIT_REASON" in raw else ""

            self.symbol_table[target] = new_name
            self.functions[target].update({
                "status": status,
                "proposed_name": new_name,
                "summary": summary,
                "revisit_reason": reason
            })
            print(f"[+] Result: {target} -> {new_name} ({status})")
            self.save_state()
        except Exception as e:
            print(f"[!] Analysis Error: {e}")

    def run_phases(self):
        # Phase 3: Bootstrap Wrappers
        wrappers = [n for n, i in self.functions.items() if i["status"] == "PENDING" and i["is_wrapper"]]
        if wrappers:
            print("\n[*] Phase 3: Bootstrapping Wrappers...")
            for w in wrappers: self.analyze_function(w)

        # Phase 4: Initial Triage
        remaining = [n for n, i in self.functions.items() if i["status"] == "PENDING" and i["string_score"] == -1]
        if remaining:
            print("\n[*] Phase 4: Initial String Triage...")
            for r in remaining:
                self.functions[r]["string_score"] = self._get_llm_string_score(self.functions[r]["body"])
            self.save_state()

        # Phase 5: LLM Directed Analysis
        print("\n[*] Phase 5: LLM-Directed Analysis Loop...")
        while True:
            target = self.llm_choose_next()
            if not target: break
            self.analyze_function(target)

if __name__ == "__main__":
    orchestrator = REOrchestrator(TARGET_BINARY, INPUT_C)
    orchestrator.run_phases()