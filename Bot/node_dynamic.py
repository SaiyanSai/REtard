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
    tqdm.write(f"[*] FIRING UP MCP SERVER FOR {target}...")
    tqdm.write("="*50)
    
    # --- PREVENT CONTEXT BLOWOUT (Token Limit) ---
    safe_code = code
    if len(safe_code) > 200000:
        tqdm.write("[!] Warning: Function code is massive. Truncating to 200KB...")
        safe_code = safe_code[:200000] + "\n// [CODE TRUNCATED DUE TO SIZE LIMIT]\n"

    global_data_c = ""
    if os.path.exists(GLOBAL_DATA_JSON):
        with open(GLOBAL_DATA_JSON, "r") as f:
            try:
                global_data_map = json.load(f)
                needed_globals = []
                for var_name, var_code in global_data_map.items():
                    # FIX 1: Exact word boundary match so DAT_1 doesn't inject DAT_1000
                    if re.search(rf'\b{re.escape(var_name)}\b', safe_code):
                        needed_globals.append(var_code)
                if needed_globals:
                    global_data_c = "// --- EXTRACTED GLOBAL DATA ---\n" + "\n".join(needed_globals) + "\n// ------------------------------\n"
                    
                    if len(global_data_c) > 200000:
                        tqdm.write(f"[*] Warning: Global data is massive. Truncating to safely fit in AI context...")
                        global_data_c = global_data_c[:200000] + "\n ... }; \n// [DATA TRUNCATED TO PREVENT TOKEN CRASH]\n"
            except Exception:
                pass

    async def run_mcp_trace():
        local_client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))
        
        mcp_script_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "ghidra_analyzer.py")
        if not os.path.exists(mcp_script_path):
            mcp_script_path = os.path.join(os.path.dirname(__file__), "ghidra_analyzer.py")
            
        mcp_client = Client(mcp_script_path)
        
        async with mcp_client:
            prompt = f"""
            You are an automated dynamic analysis pipeline. This Ghidra C code contains an obfuscated algorithm, packing logic, or a string decryption loop.
            
            1. Fix the syntax for Linux (replace Windows/Ghidra types with standard C types).
            2. Notice the global data arrays provided below. They contain the actual compressed/encrypted payload from the binary. DO NOT stub them with random bytes, USE THEM!
            3. Write a `main()` driver that allocates memory and passes it to the function.
            4. Use your `compile_and_trace` tool to execute it inside GDB.
            
            Target Function: {target}
            
            Code:
            {global_data_c}
            {safe_code}
            
            CRITICAL EXECUTION RULES:
            You are operating in an autonomous loop. The user cannot reply to you. You MUST execute the tool yourself.
            1. FIRST, output a <thinking> block explaining your driver plan.
            2. IMMEDIATELY AFTER the closing </thinking> tag, you MUST invoke the `compile_and_trace` tool. Do not ask for permission. Do not write the C code in markdown. Pass the raw C code directly into the tool call arguments.
            3. AFTER the tool returns the trace, output a final XML block:
            <analysis>
                <name>DecryptedFunctionName</name>
                <summary>Concise explanation of what the trace revealed.</summary>
                <rename>
                    <old>local_18</old><new>encrypted_buffer</new>
                </rename>
            </analysis>
            """
            
            tqdm.write(f"[*] Handing code to Gemini 2.5 Pro. Awaiting tool execution loop...")
            tqdm.write(f"[*] ⏳ NOTE: Gemini is now writing the C driver in the background.")
            tqdm.write(f"[*] ⏳ For massive entry functions, this step can take 2 to 4 minutes of silence. Please hold...")
            
            response_stream = await local_client.aio.models.generate_content_stream(
                model="gemini-2.5-pro", 
                contents=prompt,
                config=types.GenerateContentConfig(
                    tools=[mcp_client.session],
                    temperature=0.2
                )
            )
            
            full_response = ""
            first_chunk = True
            
            async for chunk in response_stream:
                if first_chunk:
                    tqdm.write("\n[*] AI stream connected! Processing live...\n")
                    first_chunk = False
                
                if getattr(chunk, 'function_calls', None):
                    for fc in chunk.function_calls:
                        tqdm.write(f"\n\n[*] ⚙️ LLM invoked tool: {fc.name}() -> Sending C driver to local GCC...")

                if chunk.text:
                    full_response += chunk.text
                    
                    if "<analysis>" not in full_response:
                        sys.stdout.write(chunk.text)
                        sys.stdout.flush()
                    elif "</analysis>" not in full_response and "<analysis>" in chunk.text:
                        pre_analysis = chunk.text.split("<analysis>")[0]
                        if pre_analysis.strip():
                            sys.stdout.write(pre_analysis + "\n")
                            sys.stdout.flush()
                        tqdm.write("\n[*] Trace analysis complete. Parsing final payload...")
                        
            return full_response

    def run_isolated():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(run_mcp_trace())
        finally:
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.close()
            asyncio.set_event_loop(None)

    try:
        trace_result = run_isolated()
        
        name_raw = extract_xml(trace_result, "name").strip().split()
        summary = extract_xml(trace_result, "summary")
        renames = re.findall(r'<rename>\s*<old>(.*?)</old>\s*<new>(.*?)</new>\s*</rename>', trace_result, re.DOTALL)
        
        new_symbols = dict(state["symbol_table"])
        placeholder_patterns = r'^(uVar|iVar|lVar|pcVar|pvVar|local_|param_|DAT_|FUN_|PTR_|D?WORD_|BYTE_)\d+'
        
        for old_val_in_code, new_val_suggested in renames:
            old_name, new_name = old_val_in_code.strip(), new_val_suggested.strip()
            
            is_lazy = any(new_name.lower().startswith(p) for p in ["some", "temp", "unknown", "var", "data", "placeholder"])
            if not is_lazy and not re.match(placeholder_patterns, new_name):
                original_key = next((k for k, v in new_symbols.items() if v == old_name), None)
                target_key = original_key if original_key else old_name
                
                if target_key not in new_symbols or new_symbols[target_key] != new_name:
                    new_symbols[target_key] = new_name
                    tqdm.write(f"[*] Dynamic Symbol Updated: {target_key} -> {new_name}")

        proposed_name = name_raw[0] if name_raw else target
        extracted_name = target
        if proposed_name != target and not proposed_name.upper().startswith("FUN_"):
            extracted_name = proposed_name
            new_symbols[target] = extracted_name
            tqdm.write(f"[*] Function Dynamically Renamed: {target} -> {extracted_name}")

        tqdm.write("\n" + "!"*60)
        tqdm.write(f"[+] DYNAMIC ANALYSIS COMPLETE FOR {extracted_name}")
        tqdm.write(f"--- FINAL SUMMARY ---\n{summary}")
        tqdm.write("!"*60 + "\n")
        
        new_functions = dict(state["functions"])
        new_target_data = dict(new_functions[target])
        new_target_data["summary"] = str(new_target_data.get("summary", "")) + f"\n\n--- DYNAMIC ANALYSIS TRACE ---\n{summary}"
        new_target_data["status"] = "ANALYZED" 
        new_functions[target] = new_target_data
        
        updated_state = dict(state)
        updated_state["functions"] = new_functions
        updated_state["symbol_table"] = new_symbols
        
        save_json_state(updated_state) 
        
        return {
            "functions": new_functions,
            "symbol_table": new_symbols,
            "history": [f"Dynamically deobfuscated {target} -> {extracted_name}"]
        }
        
    except Exception as e:
        tqdm.write(f"\n[!] MCP Execution Failed on {target}: {str(e)}\n")
        
        new_functions = dict(state["functions"])
        new_target_data = dict(new_functions[target])
        new_target_data["status"] = "ANALYZED" 
        new_functions[target] = new_target_data
        
        return {
            "functions": new_functions, 
            "history": [f"Dynamic analysis failed on {target}: {str(e)}"]
        }