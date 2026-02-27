import re
import json
import time
from pathlib import Path
from tqdm import tqdm
from state import REState
from utils import extract_xml
from config import TARGET_BINARY, STRINGS_JSON, TRIAGE_CACHE, client
from string_extract import extract_triage_data

def triage_node(state: REState):
    print("\n" + "="*30 + "\n[PHASE: TRIAGE]\n" + "="*30)
    new_functions = state["functions"].copy()
    pending = [n for n, i in new_functions.items() if i["status"] == "PENDING" and i["string_score"] == -1]
    
    if not pending: return {"phase": "analysis_loop"}

    if TARGET_BINARY and not Path(STRINGS_JSON).exists():
        print("[*] Running PyGhidra Cross-Referenced API & String Extraction...")
        try:
            extract_triage_data(TARGET_BINARY, STRINGS_JSON)
        except Exception as e:
            print(f"[!] Extraction failed: {e}")

    func_triage_map = {}
    global_context = ""
    
    if Path(STRINGS_JSON).exists():
        with open(STRINGS_JSON, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
                func_triage_map = data.get("function_map", {})
                global_strings = data.get("global_strings", [])
                
                global_strings.sort(key=len, reverse=True)
                sample_strings = global_strings[:50] 
                if sample_strings:
                    global_context = f"\n[Global Binary Context (Top 50 Longest Strings)]:\n{sample_strings}\n"
            except json.JSONDecodeError:
                pass

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
        
        tqdm.write(f"[*] Requesting Gemini Score for: {name} (APIs: {len(api_calls)}, Strings: {len(clean_strings)})")
        
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
                time.sleep(4) # THROTTLE to prevent 429
                break 
                
            except Exception as e: 
                tqdm.write(f"[!] API Error on {name} (Attempt {attempt+1}/{max_retries}): {type(e).__name__} - {str(e)}")
                if attempt < max_retries - 1:
                    tqdm.write("[*] Sleeping for 10 seconds before retrying...")
                    time.sleep(10)
                else:
                    tqdm.write(f"[-] Max retries reached for {name}. Assigning Score 0.")
                    new_functions[name]["string_score"] = 0

    return {"functions": new_functions, "phase": "analysis_loop"}