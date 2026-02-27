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

# Ensure we can import external scripts
sys.path.append(str(Path(__file__).parent))

try:
    from decompile import decompile_binary
except ImportError:
    print("[!] Ensure decompile.py is in the Bot folder.")
    sys.exit(1)

try:
    from string_extract import extract_triage_data
except ImportError:
    print("[!] Ensure string_extract.py is in the Bot folder.")
    sys.exit(1)

# --- CONFIGURATION ---
STATE_FILE = "Bot/analysis_state.json"
CHECKPOINT_DB = "Bot/graph_checkpoint.db"
TRIAGE_CACHE = "Bot/triage_cache.json"    
API_KEY = os.getenv("GEMINI_API_KEY")

# Standard client initialization
client = genai.Client(api_key=API_KEY) if API_KEY else None

# --- 1. STATE DEFINITION ---
class REState(TypedDict):
    functions: Dict[str, dict]
    symbol_table: Dict[str, str]
    current_target: str
    suggested_target: str 
    call_graph: Dict[str, List[str]]
    history: Annotated[List[str], operator.add]
    phase: str 

# --- 2. HELPERS ---
def extract_xml(text: str, tag: str) -> str:
    match = re.search(rf'<{tag}>(.*?)</{tag}>', text, re.DOTALL)
    return match.group(1).strip() if match else ""

def check_if_wrapper(name: str, body: str) -> bool:
    if not name.startswith("FUN_"): return False
    lines = [l.strip() for l in body.split('\n') if l.strip() and l not in ['{', '}'] and not l.startswith(('/', '*'))]
    if len(lines) > 12: return False
    calls = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', body)
    for target in calls:
        if not target.startswith("FUN_") and target not in ["if", "while", "for", "switch", "return"]:
            return True
    return False

def save_json_state(state: REState):
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

    binary = os.getenv("TARGET_BINARY")
    strings_json = "Bot/function_strings.json"
    
    if binary and not Path(strings_json).exists():
        print("[*] Running PyGhidra Cross-Referenced API & String Extraction...")
        try:
            extract_triage_data(binary, strings_json)
        except Exception as e:
            print(f"[!] Extraction failed: {e}")

    func_triage_map = {}
    global_context = ""
    
    if Path(strings_json).exists():
        with open(strings_json, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
                func_triage_map = data.get("function_map", {})
                global_strings = data.get("global_strings", [])
                
                global_strings.sort(key=len, reverse=True)
                sample_strings = global_strings[:50] 
                if sample_strings:
                    global_context = f"\n[Global Binary Context (Top 50 Longest Strings)]:\n{sample_strings}\n"
            except json.JSONDecodeError:
                print("[!] Failed to parse function_strings.json")

    # Load cache
    triage_cache = {}
    if Path(TRIAGE_CACHE).exists():
        with open(TRIAGE_CACHE, "r", encoding="utf-8") as f:
            try:
                triage_cache = json.load(f)
            except json.JSONDecodeError:
                pass

    for name in tqdm(pending, desc="Triaging Strings & APIs"):
        
        if name in triage_cache:
            cache_entry = triage_cache[name]
            if isinstance(cache_entry, int):
                new_functions[name]["string_score"] = cache_entry
                new_functions[name]["apis"] = []
                new_functions[name]["strings"] = []
            else:
                new_functions[name]["string_score"] = cache_entry.get("score", 0)
                new_functions[name]["apis"] = cache_entry.get("apis", [])
                new_functions[name]["strings"] = cache_entry.get("strings", [])
            continue

        body = new_functions[name]["body"]
        func_data = func_triage_map.get(name, {"strings": [], "apis": []})
        xref_strings = func_data.get("strings", [])
        api_calls = func_data.get("apis", [])
        
        inline_strings = re.findall(r'"(.*?)"', body)
        all_found_strings = list(set(xref_strings + inline_strings))
        clean_strings = [s for s in all_found_strings if len(s) > 3]
        
        new_functions[name]["apis"] = api_calls
        new_functions[name]["strings"] = clean_strings
        
        if not clean_strings and not api_calls:
            new_functions[name]["string_score"] = 0
            triage_cache[name] = {"score": 0, "apis": [], "strings": []}
            with open(TRIAGE_CACHE, "w", encoding="utf-8") as f:
                json.dump(triage_cache, f, indent=4)
            continue
            
        prompt = (
            f"Rate RE importance (0-10) of this function: {name}\n"
            f"Strings Referenced: {clean_strings}\n"
            f"Windows APIs Called: {api_calls}\n"
            f"{global_context}\n"
            f"Based on the global context, strings, and APIs used, how critical is this function for understanding the malware?\n"
            f"Return: <triage><score>VALUE</score></triage>"
        )
        
        # ---> NEW: Explicit Retry Loop with Rate Limit Throttle <---
        max_retries = 3
        for attempt in range(max_retries):
            try:
                res = client.models.generate_content(model="gemini-2.0-flash", contents=prompt)
                score = int(extract_xml(res.text, "score") or 0)
                
                new_functions[name]["string_score"] = score
                triage_cache[name] = {"score": score, "apis": api_calls, "strings": clean_strings}
                
                with open(TRIAGE_CACHE, "w", encoding="utf-8") as f:
                    json.dump(triage_cache, f, indent=4)
                    
                tqdm.write(f"[+] Triage: {name} | Score: {score}")
                
                # THROTTLE: Wait 4 seconds to stay under 15 Requests Per Minute limit
                time.sleep(4) 
                break # Success! Break out of the retry loop
                
            except Exception as e: 
                tqdm.write(f"[!] API Error on {name} (Attempt {attempt+1}/{max_retries}): {type(e).__name__} - {str(e)}")
                if attempt < max_retries - 1:
                    tqdm.write("[*] Sleeping for 10 seconds before retrying...")
                    time.sleep(10)
                else:
                    tqdm.write(f"[-] Max retries reached for {name}. Assigning Score 0.")
                    new_functions[name]["string_score"] = 0

    return {"functions": new_functions, "phase": "analysis_loop"}

def planner_node(state: REState):
    save_json_state(state)
    f = state["functions"]
    pending = [n for n in f if f[n]["status"] == "PENDING"]
    partial = [n for n in f if f[n]["status"] == "PARTIAL"]
    p_end = [n for n in f if f[n]["status"] == "PARTIAL_END"]
    
    if not pending and not partial and not p_end:
        return {"phase": "end", "current_target": None}

    sug = state.get("suggested_target")
    if sug and sug in pending:
        tqdm.write(f"[*] Following LLM breadcrumb: {sug}")
        return {"current_target": sug, "phase": "analysis_loop", "suggested_target": ""}

    if partial:
        tqdm.write(f"[*] Trail ended. Re-evaluating partial function: {partial[0]}")
        return {"current_target": partial[0], "phase": "revisit", "suggested_target": ""}

    wrappers = [n for n in pending if f[n]["is_wrapper"]]
    if wrappers:
        return {"current_target": sorted(wrappers)[0], "phase": "analysis_loop", "suggested_target": ""}

    if pending:
        target = max(pending, key=lambda n: f[n]["string_score"])
        tqdm.write(f"[*] Suggestion chain end. Anchoring to top priority function: {target} (Score: {f[target]['string_score']})")
        return {"current_target": target, "phase": "analysis_loop", "suggested_target": ""}

    if p_end:
        if state["phase"] != "final_sweep":
            print("\n" + "="*30 + "\n[PHASE: FINAL SWEEP - RESOLVING STUBBORN FUNCTIONS]\n" + "="*30)
        return {"current_target": p_end[0], "phase": "final_sweep", "suggested_target": ""}

    return {"phase": "end", "current_target": None}

def analyst_node(state: REState):
    target = state["current_target"]
    func_data = state["functions"][target]
    code = func_data["body"]
    phase = state["phase"]
    
    apis = func_data.get("apis", [])
    strings = func_data.get("strings", [])
    
    sorted_symbols = sorted(state["symbol_table"].items(), key=lambda x: len(x[0]), reverse=True)
    for old, new in sorted_symbols:
        code = re.sub(rf'\b{old}\b', new, code)

    if Path(STRINGS_JSON).exists():
        with open(STRINGS_JSON, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
                address_map = data.get("address_map", {})
                
                string_map_ints = {}
                for addr_str, val in address_map.items():
                    try:
                        string_map_ints[int(addr_str, 16)] = val
                    except ValueError: pass
                
                for m in re.finditer(r'0x([0-9a-fA-F]+)', code):
                    try:
                        addr = int(m.group(1), 16)
                        if addr in string_map_ints:
                            code = code.replace(m.group(0), f'"{string_map_ints[addr]}"')
                    except: pass
                
                for m in re.finditer(r'([A-Za-z_]+_([0-9a-fA-F]{6,16}))\b', code):
                    try:
                        addr = int(m.group(2), 16)
                        if addr in string_map_ints:
                            code = code.replace(m.group(1), f'"{string_map_ints[addr]}"')
                    except: pass
            except json.JSONDecodeError:
                pass

    instr = """STRICT RULES:
1. Return ONE logical name for the function in <name>. NO 'FUN_' prefix.
2. If you figure out what a global DAT_ variable represents, rename it using <rename><old>DAT_XXXX</old><new>g_MeaningfulName</new></rename>. You can do this multiple times.
3. Suggest the next interesting PENDING function in <suggestion>.
"""
    
    context_str = ""
    if apis or strings:
        context_str = f"Context Derived from XREFs:\n- Windows APIs Called: {apis}\n- Strings Referenced: {strings}\n\n"
    
    if phase == "final_sweep":
        prompt = f"FINAL SWEEP: Analyze {target}.\n{context_str}Code:\n{code}\n\n{instr}\nFormat: <analysis><name>Name</name><summary>Logic</summary><rename><old>DAT_...</old><new>g_...</new></rename></analysis>"
    elif phase == "revisit":
        prompt = f"Revisit {target} with context.\n{context_str}Code:\n{code}\n\n{instr}\nFormat: <analysis><name>Name</name><summary>Logic</summary><rename><old>DAT_...</old><new>g_...</new></rename></analysis>"
    else:
        prompt = f"Analyze {target}.\n{context_str}Code:\n{code}\n\n{instr}\nFormat: <analysis><name>Name</name><summary>Logic</summary><suggestion>FUN_XXXX</suggestion><rename><old>DAT_...</old><new>g_...</new></rename></analysis>"
    
    try:
        # Added a 4 second sleep here as well to respect rate limits during the Analyst Phase!
        time.sleep(4)
        res = client.models.generate_content(model="gemini-2.0-flash", contents=prompt)
        res_text = res.text
        
        name_raw = extract_xml(res_text, "name").strip().split()
        suggestion = extract_xml(res_text, "suggestion")
        summary = extract_xml(res_text, "summary")
        renames = re.findall(r'<rename>\s*<old>(.*?)</old>\s*<new>(.*?)</new>\s*</rename>', res_text, re.DOTALL)

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
        
        for old_var, new_var in renames:
            clean_old = old_var.strip()
            clean_new = new_var.strip()
            if clean_old.startswith("DAT_") and clean_old not in new_symbols:
                new_symbols[clean_old] = clean_new
                tqdm.write(f"[*] Discovered Global Variable: {clean_old} -> {clean_new}")
        
        return {"functions": new_functions, "symbol_table": new_symbols, "suggested_target": suggestion, "history": [f"Processed {target} -> {extracted_name} ({status})"]}
    except Exception as e:
        tqdm.write(f"[!] API Error on {target}: {str(e)}")
        time.sleep(10)
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