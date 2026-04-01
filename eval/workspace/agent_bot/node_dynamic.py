import asyncio
import os
import re
import sys
import json
from fastmcp import Client
from google import genai
from google.genai import types
from state import REState
from config import GLOBAL_DATA_JSON
from tqdm import tqdm
from utils import save_json_state, extract_xml

def dynamic_node(state: REState):
    target = state["current_target"]
    func_data = state["functions"][target]
    code = func_data["body"]
    
    tqdm.write(f"\n" + "="*50)
    tqdm.write(f"[*] DYNAMIC ANALYSIS FOR {target}...")
    tqdm.write("="*50)
    
    safe_code = code
    if len(safe_code) > 150000:
        safe_code = safe_code[:150000] + "\n// [CODE TRUNCATED]\n"

    base_dir = os.path.dirname(__file__)
    active_hdr_path = os.path.join(base_dir, "active_global_data.h")
    
    global_data_externs = ""
    if os.path.exists(GLOBAL_DATA_JSON):
        with open(GLOBAL_DATA_JSON, "r") as f:
            try:
                global_data_map = json.load(f)
                extern_lines = []
                for var_name, var_code in global_data_map.items():
                    if re.search(rf'\b{re.escape(var_name)}\b', safe_code):
                        match = re.match(r'(unsigned char [A-Za-z0-9_]+\[\d+\])', var_code)
                        if match:
                            extern_lines.append(f"extern {match.group(1)};")
                
                if extern_lines:
                    full_global_data_c = "\n".join(global_data_map.values()) + "\n"
                    global_data_externs = "// --- GLOBAL DATA ---\n" + "\n".join(extern_lines) + "\n// ------------------\n"
                    with open(active_hdr_path, "w") as hdr:
                        hdr.write(full_global_data_c)
            except Exception: pass

    async def run_mcp_trace():
        local_client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))
        mcp_script_path = os.path.join(base_dir, "ghidra_analyzer.py")
        mcp_client = Client(mcp_script_path)
        
        async with mcp_client:
            prompt = f"""
            You are an automated dynamic analysis pipeline. Determine the true intent of this function.
            
            1. REWRITE the function for Linux. Stub environmental checks.
            2. DRIVER: Write a `main()` that calls the function and PRINTS the final state of modified buffers to stdout.
            
            Target Function: {target}
            Global Data: {global_data_externs}
            
            Code:
            {safe_code}
            
            EXECUTION RULES:
            - Invoke `compile_and_trace` with your driver.
            - After the tool returns, output a final XML block:
            <analysis>
                <name>MeaningfulFunctionName</name>
                <summary>What the function did.</summary>
                <rename><old>old variable</old><new>new variable</new></rename>
            </analysis>
            """
            
            response_stream = await local_client.aio.models.generate_content_stream(
                model="gemini-2.5-pro", 
                contents=prompt,
                config=types.GenerateContentConfig(tools=[mcp_client.session], temperature=0.2)
            )
            
            full_response = ""
            async for chunk in response_stream:
                if chunk.text:
                    full_response += chunk.text
                    # Print everything including <thinking>
                    sys.stdout.write(chunk.text)
                    sys.stdout.flush()
                
                if getattr(chunk, 'function_calls', None):
                    for fc in chunk.function_calls:
                        tqdm.write(f"\n[*] ⚙️ LLM invoked tool: {fc.name}() -> Compiling and Running...")

            return full_response

    def run_isolated():
        loop = asyncio.new_event_loop()
        try: return loop.run_until_complete(run_mcp_trace())
        finally: loop.close()

    try:
        trace_result = run_isolated()
        
        # --- RE-IMPLEMENTED RENAMING AND STATUS UPDATES ---
        name_raw = extract_xml(trace_result, "name").strip().split()
        summary = extract_xml(trace_result, "summary")
        renames = re.findall(r'<rename>\s*<old>(.*?)</old>\s*<new>(.*?)</new>\s*</rename>', trace_result, re.DOTALL)
        
        new_symbols = dict(state["symbol_table"])
        for old, new in renames:
            old_name, new_name = old.strip(), new.strip()
            new_symbols[old_name] = new_name
            tqdm.write(f"[*] Dynamic Symbol Updated: {old_name} -> {new_name}")

        proposed_name = name_raw[0] if name_raw else target
        if proposed_name != target:
            new_symbols[target] = proposed_name
            tqdm.write(f"[*] Function Dynamically Renamed: {target} -> {proposed_name}")
        
        new_functions = dict(state["functions"])
        new_functions[target]["status"] = "ANALYZED" # Critical for progress bar
        new_functions[target]["summary"] = summary
        
        save_json_state({"functions": new_functions, "symbol_table": new_symbols})
        
        tqdm.write(f"\n[+] DYNAMIC ANALYSIS COMPLETE FOR {proposed_name}\n")
        return {"functions": new_functions, "symbol_table": new_symbols, "history": [f"Analyzed {target}"]}
    except Exception as e:
        tqdm.write(f"\n[!] Failed: {str(e)}\n")
        return {"history": [f"Failed {target}"]}