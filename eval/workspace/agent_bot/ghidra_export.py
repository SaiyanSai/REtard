import re
import json
import jarray
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def decompile_all(output_file):
    program = currentProgram
    decompinterface = DecompInterface()
    decompinterface.openProgram(program)
    monitor = ConsoleTaskMonitor()
    
    out_code = ""
    functions = program.getFunctionManager().getFunctions(True)
    
    count = 0
    for function in functions:
        res = decompinterface.decompileFunction(function, 60, monitor)
        if res.decompileCompleted():
            out_code += "// --- Function: {} @ {} ---\n".format(function.getName(), function.getEntryPoint())
            out_code += res.getDecompiledFunction().getC() + "\n\n"
            count += 1
    
    try:
        with open(output_file, "w") as f:
            f.write(out_code)
        print("[+] Successfully decompiled {} functions.".format(count))
    except Exception as e:
        print("[!] Failed to write C code: {}".format(str(e)))
        
    # --- EXTRACT ACTUAL GLOBAL MEMORY BYTES ---
    dat_matches = set(re.findall(r'DAT_([0-9a-fA-F]+)', out_code))
    ptr_matches = set(re.findall(r'PTR_([0-9a-fA-F]+)', out_code))
    
    memory = program.getMemory()
    listing = program.getListing()
    global_data = {}
    
    def fetch_data(addr_str, prefix):
        try:
            addr = program.getAddressFactory().getAddress(addr_str)
            if not addr: return
            
            data = listing.getDefinedDataAt(addr)
            # Default to 1024 bytes if undefined so AI has enough payload to unpack
            size = data.getLength() if data else 1024 
            if size > 1024 * 1024: size = 1024 * 1024 # Cap at 1MB
            
            dest = jarray.zeros(size, "b")
            bytes_read = memory.getBytes(addr, dest)
            if bytes_read > 0:
                hex_str = ", ".join(["0x%02X" % (b & 0xFF) for b in dest[:bytes_read]])
                global_data["{}{}".format(prefix, addr_str)] = "unsigned char {}{}[{}] = {{ {} }};".format(prefix, addr_str, bytes_read, hex_str)
        except Exception as e:
            pass

    for m in dat_matches: fetch_data(m, "DAT_")
    for m in ptr_matches: fetch_data(m, "PTR_")
    
    data_file = output_file.replace("decompiled_output.c", "global_data.json")
    try:
        with open(data_file, "w") as f:
            f.write(json.dumps(global_data, indent=4))
        print("[+] Successfully extracted {} global data buffers.".format(len(global_data)))
    except Exception as e:
        print("[!] Failed to write JSON: {}".format(str(e)))

if __name__ == "__main__":
    args = getScriptArgs()
    if len(args) > 0:
        output_file = args[0]
        decompile_all(output_file)
    else:
        print("Usage: ghidra_export.py <output_file>")