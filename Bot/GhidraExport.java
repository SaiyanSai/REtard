import ghidra.app.script.GhidraScript;
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
                    MemoryBlock block = memory.getBlock(addr);
                    int size = 1024;
                    if (block != null) {
                        // Read from address to the end of the section
                        long bytesLeft = block.getEnd().subtract(addr) + 1;
                        size = (int) Math.min(bytesLeft, 1024 * 1024); // Cap at 1MB
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
