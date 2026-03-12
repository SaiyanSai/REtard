import re
import time
import json
import traceback
import concurrent.futures
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
    
    placeholder_patterns = r'^(uVar|iVar|lVar|pcVar|pvVar|local_|param_|DAT_|FUN_|PTR_|D?WORD_|BYTE_)\d+'
    resolved_vars = []
    for old, new in state["symbol_table"].items():
        if re.match(placeholder_patterns, old) and not re.match(placeholder_patterns, new):
            resolved_vars.append(f"{old} -> {new}")
    
    var_context = ""
    if resolved_vars:
        var_context = "Verified Symbols (already applied to code):\n" + \
                     "\n".join([f"- {v}" for v in resolved_vars]) + "\n\n"
    
    sorted_symbols = sorted(state["symbol_table"].items(), key=lambda x: len(x[0]), reverse=True)
    for old, new in sorted_symbols:
        code = re.sub(rf'\b{old}\b', new, code)

    if Path(STRINGS_JSON).exists():
        with open(STRINGS_JSON, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
                address_map = data.get("address_map", {})
                string_map_ints = {int(addr, 16): val for addr, val in address_map.items() if addr.startswith("0x")}
                for m in re.finditer(r'0x([0-9a-fA-F]+)', code):
                    addr = int(m.group(1), 16)
                    if addr in string_map_ints:
                        code = code.replace(m.group(0), f'"{string_map_ints[addr]}"')
            except: pass

    instr = """STRICT RULES:
1. Return ONE logical name for the function in <name>.
2. Rename variables (DAT_XXXX, uVarX, local_X, etc.) in <rename> tags ONLY if you understand their specific purpose.
3. PROHIBITED: Do not use generic names like 'someGlobalValue', 'tempVar', or 'UnknownFunction'.
4. If you are unsure of the purpose of a function or variable, you MUST KEEP its original placeholder name.
5. Suggest the next interesting PENDING function in <suggestion>.
6. CRITICAL OBFUSCATION CHECK: You MUST output <is_obfuscated>True</is_obfuscated> if the code contains ANY of the following:
   - Loops performing XOR (^), bitshifts (<<, >>), or bitwise AND/OR (&, |) on arrays of data.
   - Hardcoded hex arrays being mathematically manipulated (e.g., custom string decryption).
   Even if the surrounding program looks like a normal game or application, DO NOT ignore these cryptographic signatures! If none of these are present, output <is_obfuscated>False</is_obfuscated>.
"""
    
    context_str = f"Context: APIs={apis}, Strings={strings}\n\n"
    header = f"Analyze {target}."
    if phase == "final_sweep": header = f"FINAL SWEEP: Analyze {target}."
    elif phase == "revisit": header = f"Revisit {target} with context."

    prompt = f"{header}\n{context_str}{var_context}Code:\n{code}\n\n{instr}\n"
    prompt += "Format: <analysis><name>Name</name><summary>Logic</summary><is_obfuscated>False</is_obfuscated><suggestion>FUN_...</suggestion><rename><old>...</old><new>...</new></rename></analysis>"
    
    executor = None
    try:
        time.sleep(4) 
        tqdm.write(f" -> [DEBUG] Sending Static Analysis request to Gemini...")
        
        # FIXED: Abandon thread instead of waiting for it to gracefully exit
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = executor.submit(
            client.models.generate_content,
            model="gemini-2.0-flash", 
            contents=prompt
        )
        res = future.result(timeout=25)
            
        tqdm.write(f" -> [DEBUG] Static Analysis response received.")
        res_text = res.text
        
        name_raw = extract_xml(res_text, "name").strip().split()
        suggestion = extract_xml(res_text, "suggestion")
        summary = extract_xml(res_text, "summary")
        
        is_obf_str = extract_xml(res_text, "is_obfuscated").strip().lower()
        is_obfuscated = (is_obf_str == "true")
        
        renames = re.findall(r'<rename>\s*<old>(.*?)</old>\s*<new>(.*?)</new>\s*</rename>', res_text, re.DOTALL)

        new_symbols = state["symbol_table"].copy()
        
        for old_val_in_code, new_val_suggested in renames:
            old_name, new_name = old_val_in_code.strip(), new_val_suggested.strip()
            
            is_lazy = any(new_name.lower().startswith(p) for p in ["some", "temp", "unknown", "var", "data", "placeholder"])
            if is_lazy: continue

            original_key = next((k for k, v in new_symbols.items() if v == old_name), None)
            target_key = original_key if original_key else old_name
            
            if not re.match(placeholder_patterns, new_name):
                if target_key not in new_symbols or new_symbols[target_key] != new_name:
                    new_symbols[target_key] = new_name
                    tqdm.write(f"[*] Symbol Updated: {target_key} -> {new_name}")

        proposed_name = name_raw[0] if name_raw else target
        is_generic_func = any(proposed_name.lower().startswith(p) for p in ["some", "temp", "unknown", "subroutine", "stub"])
        bad_name = proposed_name == target or proposed_name.upper().startswith("FUN_") or is_generic_func
        
        extracted_name = target
        status = "ANALYZED"

        if is_obfuscated:
            extracted_name = proposed_name if not bad_name else target
            status = "OBFUSCATED"
            tqdm.write(f"[!] Obfuscation detected in {target}. Routing to Dynamic Analysis.")
        elif bad_name:
            if phase == "final_sweep":
                extracted_name = f"UnkLogic_{target.replace('FUN_', '')}"
                status = "ANALYZED"
            else:
                extracted_name = target
                status = "PARTIAL_END"
                tqdm.write(f"[!] {target} refused rename or gave generic name. Flagged for Final Sweep.")
        else:
            extracted_name = proposed_name
            new_symbols[target] = extracted_name
            tqdm.write(f"[*] Function Renamed: {target} -> {extracted_name}")
            
            if phase not in ["revisit", "final_sweep"] and suggestion in state["functions"]:
                if state["functions"][suggestion]["status"] == "PENDING":
                    status = "PARTIAL"

        new_functions = state["functions"].copy()
        new_functions[target].update({"status": status, "summary": summary})
        
        return {
            "functions": new_functions, 
            "symbol_table": new_symbols, 
            "suggested_target": suggestion, 
            "history": [f"Processed {target} -> {extracted_name} ({status})"]
        }
    except concurrent.futures.TimeoutError:
        tqdm.write(f"[!] API TIMEOUT on {target}: Network socket hung. Retrying...")
        time.sleep(5)
        return {"history": [f"Timeout error on {target}"], "suggested_target": ""}
    except Exception as e:
        tqdm.write(f"[!] API Error on {target}: {type(e).__name__} - {str(e)}")
        tqdm.write("-" * 40)
        tqdm.write(traceback.format_exc())
        tqdm.write("-" * 40)
        time.sleep(10)
        return {"history": [f"Error on {target}: {str(e)}"], "suggested_target": ""}
    finally:
        if executor:
            # FORCE SHUTDOWN: Abandon thread immediately!
            executor.shutdown(wait=False, cancel_futures=True)