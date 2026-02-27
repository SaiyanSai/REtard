import re
import time
import json
from pathlib import Path
from tqdm import tqdm
from state import REState
from utils import extract_xml
from config import client, STRINGS_JSON

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
    
    print(f"\n{'='*60}\n[DEBUG: PROMPT FOR {target}]\n{'='*60}\n{prompt}\n{'='*60}\n")
    
    try:
        time.sleep(4) # THROTTLE
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