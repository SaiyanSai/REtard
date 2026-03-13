import os
import sys
import subprocess
import tempfile
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("GhidraDynamicAnalyzer")

def log_to_terminal(msg: str):
    """Safely print status messages to stderr so we don't break the JSON-RPC stdout pipe."""
    sys.stderr.write(f"{msg}\n")
    sys.stderr.flush()

@mcp.tool()
def compile_and_trace(c_code: str, target_function: str, compiler_flags: str = "-g -O0") -> str:
    """
    Compiles C code (driver + fixed pseudocode) and runs it via GDB to trace variables and registers.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        source_path = os.path.join(temp_dir, "source.c")
        binary_path = os.path.join(temp_dir, "program.out")
        trace_log_path = os.path.join(temp_dir, "trace.log")
        
        with open(source_path, "w") as f:
            f.write(c_code)
            
        compile_cmd = ["gcc"] + compiler_flags.split() + [source_path, "-o", binary_path]
        
        log_to_terminal(f"\n[MCP SERVER] Compiling driver: {' '.join(compile_cmd)}")
        
        try:
            subprocess.run(compile_cmd, capture_output=True, text=True, check=True)
        except subprocess.CalledProcessError as e:
            log_to_terminal("[MCP SERVER] Compilation Failed!")
            return f"Compilation Failed:\n{e.stderr}\n\nAsk the user or fix the C code and try again."
            
        gdb_script = f"""
import gdb

def trace_run():
    gdb.execute("set pagination off")
    gdb.execute("set confirm off")
    gdb.execute("tbreak {target_function}")
    
    try:
        gdb.execute("run")
    except gdb.error as e:
        with open("{trace_log_path}", "w") as f:
            f.write("Error running program: " + str(e))
        return

    with open("{trace_log_path}", "w") as f:
        f.write("=== STARTING TRACE FOR {target_function} ===\\n\\n")
        
        while True:
            try:
                frame = gdb.selected_frame()
                if frame is None:
                    break
                name = frame.name()
                
                if name != "{target_function}":
                    if name == "main": break
                    else:
                        gdb.execute("finish")
                        continue
                        
                sal = frame.find_sal()
                f.write(f"\\n--- Executing Line {{sal.line}} ---\\n")
                
                try:
                    f.write("Locals:\\n")
                    f.write(gdb.execute("info locals", to_string=True))
                except: pass
                    
                try:
                    f.write("Registers:\\n")
                    f.write(gdb.execute("info registers", to_string=True))
                except: pass
                    
                f.write("\\n")
                gdb.execute("next")
                
            except gdb.error as e:
                if "is not being run" in str(e): break
                try: gdb.execute("next")
                except: break

trace_run()
quit()
"""
        gdb_script_path = os.path.join(temp_dir, "trace.py")
        with open(gdb_script_path, "w") as f:
            f.write(gdb_script)
            
        gdb_cmd = ["gdb", "-q", "-nx", binary_path, "-x", gdb_script_path]
        
        log_to_terminal(f"[MCP SERVER] Tracing execution: {' '.join(gdb_cmd)}")
        
        subprocess.run(gdb_cmd, capture_output=True, text=True)
        
        log_to_terminal("[MCP SERVER] Trace complete.")
        
        if os.path.exists(trace_log_path):
            with open(trace_log_path, "r") as f:
                trace_content = f.read()
                
                trace_lines = trace_content.splitlines()
                
                # --- 1. TERMINAL PREVIEW (100 Lines) ---
                if len(trace_lines) > 100:
                    preview = "\n".join(trace_lines[:50]) + f"\n\n... [TRACE TRUNCATED: {len(trace_lines)-100} lines hidden from terminal] ...\n\n" + "\n".join(trace_lines[-50:])
                else:
                    preview = trace_content
                    
                log_to_terminal(f"\n=== GDB MEMORY DUMP PREVIEW ===\n{preview}\n===============================\n")
                
                # --- 2. AI CONTEXT TRUNCATION (1000 Lines) ---
                MAX_AI_LINES = 1000
                if len(trace_lines) > MAX_AI_LINES:
                    log_to_terminal(f"[MCP SERVER] ⚠️ Trace is {len(trace_lines)} lines long! Truncating to {MAX_AI_LINES} lines to protect AI context limit...")
                    
                    # Grab first 500 lines (The math setup) and last 500 lines (The final memory state)
                    head = "\n".join(trace_lines[:500])
                    tail = "\n".join(trace_lines[-500:])
                    warning_msg = f"\n\n... [MASSIVE EXECUTION LOOP DETECTED. {len(trace_lines)-MAX_AI_LINES} LINES OF TRACE REMOVED TO PREVENT TOKEN LIMIT CRASH. SHOWING FINAL MEMORY STATE BELOW] ...\n\n"
                    
                    ai_trace = head + warning_msg + tail
                else:
                    log_to_terminal("[MCP SERVER] 🧠 Uploading memory dump back to Gemini...")
                    ai_trace = trace_content
                
                log_to_terminal("[MCP SERVER] ⏳ Please wait. Gemini is analyzing the registers...")
                
                return f"--- COMMANDS RUN ---\n{' '.join(compile_cmd)}\n{' '.join(gdb_cmd)}\n\n--- TRACE ---\n{ai_trace}"
        else:
            return "Execution completed, but no trace was generated."

if __name__ == "__main__":
    mcp.run()