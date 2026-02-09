import os
import re
import json
import sys
import time
import sqlite3
from typing import TypedDict, List, Dict, Annotated
import operator
from pathlib import Path
from tqdm import tqdm
from dotenv import load_dotenv
from google import genai
from httpx import Timeout
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.sqlite import SqliteSaver

# Load environment variables
load_dotenv()

# Ensure we can import decompile.py
sys.path.append(str(Path(__file__).parent))
try:
    from decompile import decompile_binary
except ImportError:
    print("[!] Ensure decompile.py is in the Bot folder.")
    sys.exit(1)

# --- CONFIGURATION ---
STATE_FILE = "Bot/analysis_state.json"
CHECKPOINT_DB = "Bot/graph_checkpoint.db"
API_KEY = os.getenv("GEMINI_API_KEY")
client = genai.Client(api_key=API_KEY)

# --- 1. STATE DEFINITION ---
class REState(TypedDict):
    functions: Dict[str, dict]
    symbol_table: Dict[str, str]
    current_target: str
    suggested_target: str 
    call_graph: Dict[str, List[str]]
    history: Annotated[List[str], operator.add]
    phase: str # 'start', 'triage', 'analysis_loop', 'revisit', 'final_sweep', 'end'

# --- 2. HELPERS ---
def extract_xml(text: str, tag: str) -> str:
    """Safely extracts content from XML tags."""
    match = re.search(rf'<{tag}>(.*?)</{tag}>', text, re.DOTALL)
    return match.group(1).strip() if match else ""

def check_if_wrapper(name: str, body: str) -> bool:
    """Identifies small functions calling named APIs."""
    if not name.startswith("FUN_"): return False
    lines = [l.strip() for l in body.split('\n') if l.strip() and l not in ['{', '}'] and not l.startswith(('/', '*'))]
    if len(lines) > 12: return False
    calls = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', body)
    for target in calls:
        if not target.startswith("FUN_") and target not in ["if", "while", "for", "switch", "return"]:
            return True
    return False

def save_json_state(state: REState):
    """Legacy JSON export for readability."""
    data = {"functions": state["functions"], "symbol_table": state["symbol_table"]}
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

def load_json_state():
    if Path(STATE_FILE).exists():
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"functions": {}, "symbol_table": {}}

# --- 3. GRAPH NODES ---

def ingestion_node(state: REState):
    print("\n" + "="*30 + "\n[PHASE: INGESTION]\n" + "="*30)
    binary = os.getenv("TARGET_BINARY")
    output_c = "Bot/decompiled_output.c"
    prev = load_json_state()
    
    if not Path(output_c).exists():
        decompile_binary(binary, output_c)

    functions = prev.get("functions", {})
    symbol_table = prev.get("symbol_table", {})
    
    with open(output_c, "r", encoding="utf-8") as f:
        content = f.read()

    pattern = r"// --- Function: (FUN_.*?) @ (.*?) ---\n(.*?)(?=\n// --- Function:|\Z)"
    matches = re.findall(pattern, content, re.DOTALL)

    for name, addr, body in matches:
        if name not in functions:
            body_text = body.strip()
            functions[name] = {
                "address": addr, "body": body_text,
                "status": "PENDING", "string_score": -1,
                "is_wrapper": check_if_wrapper(name, body_text),
                "summary": ""
            }
    return {"functions": functions, "symbol_table": symbol_table, "phase": "triage", "history": [f"Ingested {len(functions)} functions."]}

def triage_node(state: REState):
    print("\n" + "="*30 + "\n[PHASE: TRIAGE]\n" + "="*30)
    new_functions = state["functions"].copy()
    pending = [n for n, i in new_functions.items() if i["status"] == "PENDING" and i["string_score"] == -1]
    
    if not pending: return {"phase": "analysis_loop"}

    for name in tqdm(pending, desc="Triaging Strings"):
        strings = re.findall(r'"(.*?)"', new_functions[name]["body"])
        clean = [s for s in strings if len(s) > 3]
        if not clean:
            new_functions[name]["string_score"] = 0
            continue
        prompt = f"Rate RE importance (0-10) of strings in {name}:\n{clean}\n\nReturn: <triage><score>VALUE</score></triage>"
        try:
            res = client.models.generate_content(model="gemini-2.0-flash", contents=prompt)
            score = int(extract_xml(res.text, "score") or 0)
            new_functions[name]["string_score"] = score
            tqdm.write(f"[*] Triage: {name} | Score: {score} | Strings: {clean}")
        except: new_functions[name]["string_score"] = 0

    return {"functions": new_functions, "phase": "analysis_loop"}

def planner_node(state: REState):
    """
    STRICT PRIORITY: 
    1. Suggestions (PENDING)
    2. Trail Revisit (PARTIAL)
    3. Wrappers (PENDING)
    4. Strings (PENDING)
    5. Final Sweep (PARTIAL_END)
    """
    save_json_state(state)
    f = state["functions"]
    pending = [n for n in f if f[n]["status"] == "PENDING"]
    partial = [n for n in f if f[n]["status"] == "PARTIAL"]
    p_end = [n for n in f if f[n]["status"] == "PARTIAL_END"]
    
    if not pending and not partial and not p_end:
        return {"phase": "end", "current_target": None}

    # 1. Breadcrumb Suggestion
    sug = state.get("suggested_target")
    if sug and sug in pending:
        tqdm.write(f"[*] Following LLM breadcrumb: {sug}")
        return {"current_target": sug, "phase": "analysis_loop", "suggested_target": ""}

    # 2. Revisit Trail Parent (PARTIAL)
    if partial:
        tqdm.write(f"[*] Trail ended. Re-evaluating partial function: {partial[0]}")
        return {"current_target": partial[0], "phase": "revisit", "suggested_target": ""}

    # 3. Wrappers
    wrappers = [n for n in pending if f[n]["is_wrapper"]]
    if wrappers:
        return {"current_target": sorted(wrappers)[0], "phase": "analysis_loop", "suggested_target": ""}

    # 4. String Anchor
    if pending:
        target = max(pending, key=lambda n: f[n]["string_score"])
        tqdm.write(f"[*] Suggestion chain end. Anchoring to top string: {target} (Score: {f[target]['string_score']})")
        return {"current_target": target, "phase": "analysis_loop", "suggested_target": ""}

    # 5. Final Sweep
    if p_end:
        if state["phase"] != "final_sweep":
            print("\n" + "="*30 + "\n[PHASE: FINAL SWEEP - RESOLVING STUBBORN FUNCTIONS]\n" + "="*30)
        return {"current_target": p_end[0], "phase": "final_sweep", "suggested_target": ""}

    return {"phase": "end", "current_target": None}

def analyst_node(state: REState):
    target = state["current_target"]
    code = state["functions"][target]["body"]
    phase = state["phase"]
    
    for old, new in state["symbol_table"].items():
        code = re.sub(rf'\b{old}\b', new, code)

    instr = "STRICT: Return ONE logical name in <name>. NO 'FUN_' prefix. Guess if unsure."
    
    if phase == "final_sweep":
        prompt = f"FINAL SWEEP: Analyze {target}.\nCode:\n{code}\n\n{instr}\nFormat: <analysis><name>Name</name><summary>Logic</summary></analysis>"
    elif phase == "revisit":
        prompt = f"Revisit {target} with context.\nCode:\n{code}\n\n{instr}\nFormat: <analysis><name>Name</name><summary>Logic</summary></analysis>"
    else:
        prompt = f"Analyze {target}.\nCode:\n{code}\n\n{instr}\nSuggest PENDING sub-call in <suggestion>.\nFormat: <analysis><name>Name</name><summary>Logic</summary><suggestion>FUN_XXXX</suggestion></analysis>"
    
    try:
        res = client.models.generate_content(model="gemini-2.0-flash", contents=prompt)
        res_text = res.text
        name_raw = extract_xml(res_text, "name").strip().split()
        suggestion = extract_xml(res_text, "suggestion")
        summary = extract_xml(res_text, "summary")

        # Validation logic
        bad_name = not name_raw or name_raw[0].upper().startswith("FUN_") or name_raw[0] == target
        
        if bad_name:
            if phase == "final_sweep":
                extracted_name = f"UnkLogic_{target.replace('FUN_', '')}"
                status = "ANALYZED"
            else:
                extracted_name = target
                status = "PARTIAL_END"
                tqdm.write(f"[!] {target} refused rename. Flagged for Final Sweep.")
        else:
            extracted_name = name_raw[0]
            status = "ANALYZED"
            if phase not in ["revisit", "final_sweep"] and suggestion in state["functions"]:
                if state["functions"][suggestion]["status"] == "PENDING":
                    status = "PARTIAL"

        new_functions = state["functions"].copy()
        new_functions[target].update({"status": status, "summary": summary})
        new_symbols = state["symbol_table"].copy()
        new_symbols[target] = extracted_name
        
        return {"functions": new_functions, "symbol_table": new_symbols, "suggested_target": suggestion, "history": [f"Processed {target} -> {extracted_name} ({status})"]}
    except Exception as e:
        if "429" in str(e): time.sleep(10)
        return {"history": [f"Error on {target}: {str(e)}"], "suggested_target": ""}

# --- 4. GRAPH CONSTRUCTION ---
builder = StateGraph(REState)
builder.add_node("ingestor", ingestion_node); builder.add_node("triager", triage_node)
builder.add_node("planner", planner_node); builder.add_node("analyst", analyst_node)
builder.set_entry_point("ingestor")
builder.add_edge("ingestor", "triager"); builder.add_edge("triager", "planner"); builder.add_edge("analyst", "planner")
builder.add_conditional_edges("planner", lambda x: "end" if x["phase"] == "end" else "continue", {"end": END, "continue": "analyst"})

if __name__ == "__main__":
    with SqliteSaver.from_conn_string(CHECKPOINT_DB) as saver:
        graph = builder.compile(checkpointer=saver)
        config = {"configurable": {"thread_id": "spider_v12"}}
        initial_state = {"functions": {}, "symbol_table": {}, "current_target": "", "suggested_target": "", "call_graph": {}, "history": [], "phase": "start"}
        pbar = None
        for event in graph.stream(initial_state, config=config):
            for node, output in event.items():
                if node == "ingestor" and not pbar:
                    pbar = tqdm(total=len(output["functions"]), initial=len(output["symbol_table"]), desc="Total Progress")
                if node == "analyst" and pbar and any("ANALYZED" in h for h in output.get("history", [])):
                    pbar.update(1)
                if "history" in output: tqdm.write(f"[{node.upper()}] {output['history'][-1]}")
        if pbar: pbar.close()