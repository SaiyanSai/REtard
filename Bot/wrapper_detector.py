import re
from pathlib import Path

INPUT_C = "/home/saiyansai/RE/Bot/decompiled_output.c"
OUTPUT_TXT = "/home/saiyansai/RE/Bot/boilerplate.txt"

def identify_wrappers(file_path):
    if not Path(file_path).exists():
        return []

    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    pattern = r"// --- Function: (.*?) @ (.*?) ---\n(.*?)(?=\n// --- Function:|\Z)"
    matches = re.findall(pattern, content, re.DOTALL)
    wrappers = []
    
    decl_pattern = r'^(int|char|long|float|double|uint|short|byte|undefined[1248]|void|va_list|LPCSTR|HANDLE|HWND|LPSTR)\s+\*?[a-zA-Z0-9_]+(\[[0-9]+\])?;'

    for name, addr, body in matches:
        body_lines = body.strip().split('\n')
        logic_lines = []
        has_brace = False
        
        for line in body_lines:
            line = line.strip()
            if not line or line.startswith('/') or line.startswith('*'): continue
            if line == '{': 
                has_brace = True
                continue
            if line == '}': continue
            if not has_brace: continue
            if re.match(decl_pattern, line): continue
            logic_lines.append(line)

        is_small = len(logic_lines) <= 10
        has_api_call = bool(re.search(r'(_imp_|__mingw|___|(?<=[^a-zA-Z0-9_])[a-zA-Z0-9_]+(?=\())', body))
        is_stub = len(logic_lines) <= 1 and any(x in body for x in ["return;", "return 0;"])
        is_passthrough = len(logic_lines) <= 3 and body.count('(') >= 1

        if is_small and (has_api_call or is_stub or is_passthrough):
            wrappers.append((addr, name))

    with open(OUTPUT_TXT, "w") as f:
        for addr, name in wrappers:
            f.write(f"{addr},{name}\n")
    
    print(f"[+] Saved {len(wrappers)} functions to {OUTPUT_TXT}")
    return wrappers

if __name__ == "__main__":
    identify_wrappers(INPUT_C)