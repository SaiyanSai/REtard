import os
import json
from pathlib import Path
from collections import defaultdict
import pyghidra

GHIDRA_INSTALL = Path("ghidra_12.0.1_PUBLIC")
os.environ["GHIDRA_INSTALL_DIR"] = str(GHIDRA_INSTALL)

pyghidra.start(install_dir=GHIDRA_INSTALL)

def extract_triage_data(binary_path, output_json):
    bin_path = Path(binary_path)
    project_dir = Path("ghidra_projects")
    
    print(f"[*] Opening existing project at: {project_dir}")
    
    with pyghidra.open_project(project_dir, "AutomatedDecomp", create=False) as project:
        project_path = f"/{bin_path.name}"
        
        with pyghidra.program_context(project, project_path) as program:
            print(f"[*] Ensuring analysis is complete on {program.getName()}...")
            pyghidra.analyze(program)
            
            from ghidra.program.util import DefinedStringIterator
            from ghidra.util.task import TaskMonitor
            
            ref_manager = program.getReferenceManager()
            func_manager = program.getFunctionManager()
            
            # This will hold BOTH strings and API calls for each function
            function_triage_data = defaultdict(lambda: {"strings": [], "apis": []})
            global_strings = []
            
            # --- 1. EXTRACT API CALLS ---
            print("[*] Extracting API Calls per function...")
            monitor = TaskMonitor.DUMMY
            for func in func_manager.getFunctions(True): # True means forward iteration
                func_name = func.getName()
                
                # Get all functions called by this function
                called_funcs = func.getCalledFunctions(monitor)
                for called in called_funcs:
                    # If the called function is an external import (like MessageBoxA)
                    if called.isExternal() or called.isThunk():
                        api_name = called.getName()
                        if api_name not in function_triage_data[func_name]["apis"]:
                            function_triage_data[func_name]["apis"].append(api_name)
            
            # --- 2. EXTRACT STRINGS (Deep XREF) ---
            def get_referencing_functions(addr, depth=0, max_depth=4, visited=None):
                if visited is None: visited = set()
                if addr in visited: return set()
                visited.add(addr)
                
                found_funcs = set()
                if depth > max_depth: return found_funcs
                    
                for ref in ref_manager.getReferencesTo(addr):
                    from_addr = ref.getFromAddress()
                    func = func_manager.getFunctionContaining(from_addr)
                    if func:
                        found_funcs.add(func.getName())
                    else:
                        found_funcs.update(get_referencing_functions(from_addr, depth + 1, max_depth, visited))
                return found_funcs

            print("[*] Extracting Strings via Deep XREFs...")
            for string_data in DefinedStringIterator.forProgram(program):
                addr = string_data.getMinAddress()
                raw_val = string_data.getValue()
                if not raw_val: continue
                
                str_val = str(raw_val)
                if len(str_val) < 4: continue
                
                global_strings.append(str_val)
                
                funcs = get_referencing_functions(addr)
                for func_name in funcs:
                    if str_val not in function_triage_data[func_name]["strings"]:
                        function_triage_data[func_name]["strings"].append(str_val)
            
            # --- 3. SAVE TO JSON ---
            output_data = {
                "global_strings": list(set(global_strings)),
                "function_map": dict(function_triage_data)
            }
            
            print(f"[*] Saving triage map to: {output_json}")
            with open(output_json, "w", encoding="utf-8") as f:
                json.dump(output_data, f, indent=4)
                
            print(f"[+] Extracted data for {len(function_triage_data)} functions.")

if __name__ == "__main__":
    TARGET_FILE = "spider.exe"
    RESULT_FILE = "Bot/function_strings.json" # Reusing the same filename for your orchestrator

    if not Path(TARGET_FILE).exists():
        print(f"Error: File {TARGET_FILE} not found.")
    else:
        extract_triage_data(TARGET_FILE, RESULT_FILE)