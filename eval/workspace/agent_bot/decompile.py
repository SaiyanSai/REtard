import os
import subprocess
from config import GHIDRA_PATH, PROJECT_DIR, PROJECT_NAME

GHIDRA_JAVA_SCRIPT = r"""import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.HashSet;
import java.util.Set;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class GhidraExport extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0) return;
        String outputFile = args[0];
        PrintWriter writer = new PrintWriter(new FileWriter(new File(outputFile)));

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
        int count = 0;
        StringBuilder allCode = new StringBuilder();

        while (funcs.hasNext()) {
            Function func = funcs.next();
            DecompileResults res = decomp.decompileFunction(func, 60, monitor);
            if (res.decompileCompleted()) {
                String code = res.getDecompiledFunction().getC();
                String header = "// --- Function: " + func.getName() + " @ " + func.getEntryPoint() + " ---\n";
                writer.println(header + code + "\n");
                allCode.append(header).append(code).append("\n");
                count++;
            }
        }
        writer.close();
        println("[+] Successfully decompiled " + count + " functions.");

        // Extract Global Data matches
        String codeStr = allCode.toString();
        Set<String> addresses = new HashSet<>();
        Matcher m = Pattern.compile("(DAT|PTR)_([0-9a-fA-F]+)").matcher(codeStr);
        while (m.find()) {
            addresses.add(m.group(0));
        }

        Map<String, String> globalData = new HashMap<>();
        Memory memory = currentProgram.getMemory();

        for (String match : addresses) {
            String prefix = match.substring(0, 4);
            String addrStr = match.substring(4);
            try {
                Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
                if (addr != null) {
                    
                    long size = 1024; 
                    MemoryBlock block = memory.getBlock(addr);
                    if (block != null) {
                        long bytesLeft = block.getEnd().subtract(addr) + 1;
                        size = Math.min(bytesLeft, 1024 * 1024); // Cap at 1MB
                    }
                    
                    byte[] dest = new byte[(int)size];
                    int bytesRead = memory.getBytes(addr, dest);
                    
                    if (bytesRead > 0) {
                        int actualLen = bytesRead;
                        while (actualLen > 1 && dest[actualLen - 1] == 0) {
                            actualLen--;
                        }
                        
                        StringBuilder hexStr = new StringBuilder();
                        for (int i = 0; i < actualLen; i++) {
                            if (i > 0) hexStr.append(", ");
                            hexStr.append(String.format("0x%02X", dest[i]));
                        }
                        
                        String decl = "unsigned char " + prefix + addrStr + "[" + bytesRead + "] = { " + hexStr.toString() + " };";
                        globalData.put(match, decl);
                    }
                }
            } catch (Exception e) {}
        }

        String jsonFile = outputFile.replace("decompiled_output.c", "global_data.json");
        PrintWriter jWriter = new PrintWriter(new FileWriter(new File(jsonFile)));
        jWriter.println("{");
        int i = 0;
        for (Map.Entry<String, String> entry : globalData.entrySet()) {
            jWriter.print("  \"" + entry.getKey() + "\": \"" + entry.getValue().replace("\"", "\\\"") + "\"");
            if (i < globalData.size() - 1) jWriter.println(",");
            else jWriter.println();
            i++;
        }
        jWriter.println("\n}");
        jWriter.close();
        println("[+] Successfully extracted " + globalData.size() + " global data buffers.");
    }
}
"""

def decompile_binary(binary_path: str, output_file: str):
    binary_path_abs = os.path.abspath(binary_path)
    output_file_abs = os.path.abspath(output_file)
    project_dir_abs = os.path.abspath(PROJECT_DIR)

    if not os.path.exists(project_dir_abs):
        os.makedirs(project_dir_abs)

    print(f"[*] Opening project at: {project_dir_abs}")
    print(f"[*] Importing binary: {binary_path_abs}")
    print(f"[*] Running auto-analysis on {binary_path_abs}...")
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    script_name = "GhidraExport.java"
    script_path = os.path.join(script_dir, script_name)
    
    with open(script_path, "w") as f:
        f.write(GHIDRA_JAVA_SCRIPT)
        
    # Attempt 1: Standard Auto-Detect (For PE / DLL / ELF files)
    cmd_auto = [
        GHIDRA_PATH,
        project_dir_abs,
        PROJECT_NAME,
        "-import", binary_path_abs,
        "-overwrite",
        "-scriptPath", script_dir,
        "-postScript", script_name, output_file_abs
    ]
    
    # Attempt 2: Raw Binary Fallback (For pure shellcode without headers)
    cmd_raw = [
        GHIDRA_PATH,
        project_dir_abs,
        PROJECT_NAME,
        "-import", binary_path_abs,
        "-overwrite",
        "-loader", "Raw Binary", 
        "-processor", "x86:LE:64:default",
        "-scriptPath", script_dir,
        "-postScript", script_name, output_file_abs
    ]
    
    print("[*] Initializing Decompiler (Auto-Detect Mode)...")
    
    # Run silently first to see if it succeeds
    result = subprocess.run(cmd_auto, capture_output=True, text=True)
    
    if result.returncode == 0:
        # Success! It was a properly formatted executable. Print the logs.
        print(result.stdout)
        print(f"[*] Decompiling finished. Output at: {output_file_abs}")
    else:
        # It failed. It is likely raw shellcode.
        print("[!] Auto-detect failed. File lacks PE/ELF headers (likely raw shellcode).")
        print("[*] Restarting Ghidra and forcing x86-64 Raw Binary Loader...")
        
        try:
            # Run openly so the user sees the output this time
            subprocess.run(cmd_raw, check=True)
            print(f"[*] Decompiling finished. Output at: {output_file_abs}")
        except subprocess.CalledProcessError:
            print(f"[!] Ghidra headless error occurred in BOTH modes. Please check your payload file.")