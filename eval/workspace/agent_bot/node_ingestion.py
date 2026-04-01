import re
from pathlib import Path
from state import REState
from utils import load_json_state, check_if_wrapper
from config import TARGET_BINARY, OUTPUT_C
from decompile import decompile_binary

def is_function_empty_or_boilerplate(body_text: str) -> bool:
    """Returns True if the function is just 'return;', empty, or compiler boilerplate."""
    # Strip comments out to see the real logic
    clean_body = re.sub(r'/\*.*?\*/', '', body_text, flags=re.DOTALL)
    clean_body = re.sub(r'//.*', '', clean_body)
    
    # Extract actual executable statements
    statements = [line.strip() for line in clean_body.split('\n') if line.strip() and line.strip() not in ('{', '}')]
    
    if not statements:
        return True
    if len(statements) == 1 and statements[0] == 'return;':
        return True
    if any('halt_baddata' in s for s in statements):
        return True
        
    return False

def ingestion_node(state: REState):
    print("\n" + "="*30 + "\n[PHASE: INGESTION]\n" + "="*30)
    
    if not Path(OUTPUT_C).exists():
        decompile_binary(TARGET_BINARY, OUTPUT_C)

    prev = load_json_state()
    functions = prev.get("functions", {})
    symbol_table = prev.get("symbol_table", {})
    
    with open(OUTPUT_C, "r", encoding="utf-8") as f:
        content = f.read()

    pattern = r"// --- Function: (FUN_.*?|_?main|_?entry|DllMain|WinMain|wmain|wWinMain) @ (.*?) ---\n(.*?)(?=\n// --- Function:|\Z)"
    matches = re.findall(pattern, content, re.DOTALL)

    for name, addr, body in matches:
        name = name.strip()
        body_text = body.strip()
        
        # FIXED: Ignore empty and boilerplate functions completely
        if is_function_empty_or_boilerplate(body_text):
            continue
            
        if name not in functions:
            functions[name] = {
                "address": addr, 
                "body": body_text,
                "status": "PENDING", 
                "string_score": -1,
                "is_wrapper": check_if_wrapper(name, body_text),
                "summary": ""
            }
            
    return {
        "functions": functions, 
        "symbol_table": symbol_table, 
        "phase": "triage", 
        "history": [f"Ingested {len(functions)} target functions."]
    }