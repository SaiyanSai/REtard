"""
ghidra_decompile.py  –  Run Ghidra headless on a binary and write a decompiled-C output file.
"""

import subprocess
from pathlib import Path

GHIDRA_JAVA_SCRIPT = r"""import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.address.Address;
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

        // Extract Global Data
        String codeStr = allCode.toString();
        Set<String> addresses = new HashSet<>();
        Matcher m = Pattern.compile("(DAT|PTR)_([0-9a-fA-F]+)").matcher(codeStr);
        while (m.find()) { addresses.add(m.group(0)); }

        Map<String, String> globalData = new HashMap<>();
        Memory memory = currentProgram.getMemory();

        for (String match : addresses) {
            String prefix = match.substring(0, 4);
            String addrStr = match.substring(4);
            try {
                Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
                if (addr != null) {
                    MemoryBlock block = memory.getBlock(addr);
                    int size = 1024;
                    if (block != null) {
                        long bytesLeft = block.getEnd().subtract(addr) + 1;
                        size = (int) Math.min(bytesLeft, 1024 * 1024);
                    }
                    byte[] dest = new byte[size];
                    int bytesRead = memory.getBytes(addr, dest);
                    if (bytesRead > 0) {
                        StringBuilder hexStr = new StringBuilder();
                        for (int i = 0; i < bytesRead; i++) {
                            if (i > 0) hexStr.append(", ");
                            hexStr.append(String.format("0x%02X", dest[i]));
                        }
                        String decl = "unsigned char " + prefix + addrStr + "[" + bytesRead + "] = { " + hexStr.toString() + " };";
                        globalData.put(match, decl);
                    }
                }
            } catch (Exception e) {}
        }

        // FIXED: Dynamically generate json filename instead of hardcoded replace
        String jsonFile = outputFile.substring(0, outputFile.lastIndexOf('.')) + "_global_data.json";
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

def decompile_binary(
    binary_path:   str | Path,
    output_c:      str | Path,
    ghidra_path:   str,
    project_dir:   str | Path | None = None,
    project_name:  str = "EvalProject",
) -> Path:
    binary_path = Path(binary_path).resolve()
    output_c    = Path(output_c).resolve()
    output_c.parent.mkdir(parents=True, exist_ok=True)

    if project_dir is None:
        project_dir = output_c.parent / "ghidra_project"
    project_dir = Path(project_dir).resolve()
    project_dir.mkdir(parents=True, exist_ok=True)

    script_path = output_c.parent / "GhidraExport.java"
    script_path.write_text(GHIDRA_JAVA_SCRIPT)

    cmd = [
        ghidra_path,
        str(project_dir),
        project_name,
        "-import",   str(binary_path),
        "-overwrite",
        "-scriptPath", str(output_c.parent),
        "-postScript", "GhidraExport.java", str(output_c),
    ]

    print(f"[ghidra] Decompiling {binary_path.name} …")
    result = subprocess.run(cmd, capture_output=False, text=True)

    if result.returncode != 0:
        raise RuntimeError(f"Ghidra headless failed (exit {result.returncode}).")

    if not output_c.exists():
        raise FileNotFoundError(f"Ghidra ran but {output_c} was not created.")

    print(f"[ghidra] ✔  Decompiled → {output_c}  ({output_c.stat().st_size} bytes)")
    return output_c


def decompile_both(
    debug_binary:    str | Path,
    stripped_binary: str | Path,
    workspace:       str | Path,
    ghidra_path:     str,
) -> tuple[Path, Path]:
    ws = Path(workspace)
    debug_out   = ws / "debug_decompiled.c"
    stripped_out = ws / "stripped_decompiled.c"

    print("\n[ghidra] ── Decompiling DEBUG binary ─────────────────────────────")
    decompile_binary(debug_binary, debug_out, ghidra_path, project_dir=ws / "ghidra_debug", project_name="EvalDebug")

    print("\n[ghidra] ── Decompiling STRIPPED binary ──────────────────────────")
    decompile_binary(stripped_binary, stripped_out, ghidra_path, project_dir=ws / "ghidra_stripped", project_name="EvalStripped")

    return debug_out, stripped_out