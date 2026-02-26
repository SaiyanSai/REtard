import os
from pathlib import Path
import pyghidra

# 1. INITIALIZE PYGHIDRA
GHIDRA_INSTALL = Path("ghidra_12.0.1_PUBLIC")
os.environ["GHIDRA_INSTALL_DIR"] = str(GHIDRA_INSTALL)

# start() initializes the JVM
pyghidra.start(install_dir=GHIDRA_INSTALL)

def decompile_binary(binary_path, output_path):
    bin_path = Path(binary_path)
    # Using the RE folder for projects to keep things organized
    project_dir = Path("ghidra_projects")
    os.makedirs(project_dir, exist_ok=True)

    print(f"[*] Opening project at: {project_dir}")
    
    with pyghidra.open_project(project_dir, "AutomatedDecomp", create=True) as project:
        
        # 2. IMPORT BINARY (Fixed Overload)
        # We cast bin_path to str() so JPype knows to use the String overload
        print(f"[*] Importing binary: {bin_path.name}")
        
        # Check if file already exists in project to avoid duplicate import errors
        project_path = f"/{bin_path.name}"
        
        try:
            # Use the Builder pattern from the documentation
            loader = pyghidra.program_loader().project(project).source(str(bin_path))
            with loader.load() as load_results:
                # Save the imported program to the project
                load_results.save(pyghidra.task_monitor())
        except Exception as e:
            # If it already exists, we just continue to the context
            print(f"[*] Note: Binary might already be in project, proceeding...")

        # 3. ACCESS PROGRAM CONTEXT
        with pyghidra.program_context(project, project_path) as program:
            
            # 4. RUN ANALYSIS
            print(f"[*] Running auto-analysis on {program.getName()}...")
            pyghidra.analyze(program)
            
            # 5. DECOMPILATION
            from ghidra.app.decompiler import DecompInterface
            from ghidra.util.task import ConsoleTaskMonitor
            
            print(f"[*] Initializing Decompiler...")
            decomp_interface = DecompInterface()
            decomp_interface.openProgram(program)
            
            fm = program.getFunctionManager()
            functions = fm.getFunctions(True)
            
            count = 0
            print(f"[*] Decompiling to: {output_path}")
            with open(output_path, "w", encoding="utf-8") as f:
                for func in functions:
                    if func.isThunk():
                        continue
                        
                    # 60-second timeout
                    results = decomp_interface.decompileFunction(func, 60, ConsoleTaskMonitor())
                    
                    if results.decompileCompleted():
                        c_code = results.getDecompiledFunction().getC()
                        f.write(f"// --- Function: {func.getName()} @ {func.getEntryPoint()} ---\n")
                        f.write(c_code)
                        f.write("\n\n")
                        count += 1
            
            decomp_interface.dispose()
            print(f"[+] Successfully decompiled {count} functions.")

if __name__ == "__main__":
    TARGET_FILE = "/home/saiyansai/RE/crackme.exe"
    RESULT_FILE = "/home/saiyansai/RE/Bot/decompiled_output.c"

    if not Path(TARGET_FILE).exists():
        print(f"Error: File {TARGET_FILE} not found.")
    else:
        decompile_binary(TARGET_FILE, RESULT_FILE)