import asyncio
import os
import re
import sys
from fastmcp import Client
from google.genai import types
from state import REState
from config import client
from tqdm import tqdm
from utils import save_json_state, extract_xml

def dynamic_node(state: REState):
    target = state["current_target"]
    func_data = state["functions"][target]
    code = func_data["body"]
    
    tqdm.write(f"\n" + "="*50)
    tqdm.write(f"[*] FIRING UP MCP SERVER FOR {target}...")
    tqdm.write("="*50)

    async def run_mcp_trace():
        mcp_script_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "ghidra_analyzer.py")
        if not os.path.exists(mcp_script_path):
            mcp_script_path = os.path.join(os.path.dirname(__file__), "ghidra_analyzer.py")
            
        mcp_client = Client(mcp_script_path)
        
        async with mcp_client:
            prompt = f"""
            You are an automated dynamic analysis pipeline. This Ghidra C code contains an obfuscated algorithm, packing logic, or a string decryption loop.
            
            1. Fix the syntax for Linux (replace Windows/Ghidra types with standard C types).
            2. Write a `main()` driver that allocates memory and passes it to the function.
            3. Use your `compile_and_trace` tool to execute it inside GDB.
            
            Target Function: {target}
            
            Code:
            {code}
            
            EXECUTION INSTRUCTIONS (STRICT ORDER):
            1. FIRST, output a <thinking> block explaining what this function does and how you plan to write the C driver.
            2. THEN, invoke the `compile_and_trace` tool.
            3. AFTER the tool finishes, output a second <thinking> block explaining the memory trace results.
            4. FINALLY, output your findings strictly in this XML format:
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
            
            response_stream = await client.aio.models.generate_content_stream(
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

    try:
        trace_result = asyncio.run(run_mcp_trace())
        
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