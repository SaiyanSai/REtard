import os
import sys
import subprocess
import tempfile
import shutil

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("GhidraDynamicAnalyzer")

def log_to_terminal(msg: str):
    sys.stderr.write(f"{msg}\n"); sys.stderr.flush()

@mcp.tool()
def compile_and_trace(c_code: str, target_function: str, compiler_flags: str = "-g -O0") -> str:
    """
    Compiles C code and runs it natively, returning the standard output.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        source_path = os.path.join(temp_dir, "source.c")
        binary_path = os.path.join(temp_dir, "program.out")
        
        base_dir = os.path.dirname(__file__)
        active_header_path = os.path.join(base_dir, "active_global_data.h")
        
        full_code = c_code + "\n\n"
        if os.path.exists(active_header_path):
            with open(active_header_path, "r") as f:
                full_code = f.read() + "\n\n" + full_code 
        
        with open(source_path, "w") as f: f.write(full_code)
            
        compile_cmd = ["gcc"] + compiler_flags.split() + [source_path, "-o", binary_path]
        log_to_terminal(f"\n[MCP] Compiling Driver...")
        
        try:
            # Capture compilation errors
            cp = subprocess.run(compile_cmd, capture_output=True, text=True, cwd=temp_dir)
            if cp.returncode != 0:
                log_to_terminal("[MCP] Compilation Failed!")
                return f"--- COMPILATION ERROR ---\n{cp.stderr}"
        except Exception as e:
            return f"Internal Error: {str(e)}"

        log_to_terminal("[MCP] Running natively...")
        output = ""
        try:
            # Run the binary and capture stdout
            result = subprocess.run(f"{binary_path}", shell=True, cwd=temp_dir, timeout=10, capture_output=True, text=True)
            output = result.stdout
            if result.stderr:
                output += "\n" + result.stderr
            
            log_to_terminal(f"[MCP] Execution Successful. Output length: {len(output)}")
        except subprocess.TimeoutExpired:
            output = "Execution Error: Timeout (10s)"
        except Exception as e:
            output = f"Execution Error: {str(e)}"

        # We return the output wrapped in a clear header for the AI to see
        return f"--- NATIVE EXECUTION OUTPUT ---\n{output}\n-------------------------------"

if __name__ == "__main__":
    mcp.run()