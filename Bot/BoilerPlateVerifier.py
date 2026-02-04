import os
import re
from pathlib import Path
from google import genai

# Configuration using your existing environment
API_KEY = "AIzaSyDnYVLmgbAd28dZI-jBK3GB5uQX1OudmVs"
client = genai.Client(api_key=API_KEY)

INPUT_C = "/home/saiyansai/RE/Bot/decompiled_output.c"
BOILERPLATE_FILE = "/home/saiyansai/RE/Bot/boilerplate.txt"

def verify_and_rename():
    if not Path(BOILERPLATE_FILE).exists():
        print("[!] No boilerplate list found. Run wrapper_detector.py first.")
        return

    with open(BOILERPLATE_FILE, "r") as f:
        targets = [line.strip().split(',') for line in f if line.strip()]

    with open(INPUT_C, "r") as f:
        full_content = f.read()

    total_targets = len(targets)
    print(f"[*] Verifying {total_targets} potential boilerplate functions...")

    for i, (addr, name) in enumerate(targets):
        # Progress Shower
        print(f"[*] Analyzing function {i+1}/{total_targets}: {name}")

        # Extract function body using regex
        pattern = rf"// --- Function: {re.escape(name)} @ {re.escape(addr)} ---\n(.*?)(?=\n// --- Function:|\Z)"
        match = re.search(pattern, full_content, re.DOTALL)
        if not match: 
            print(f"[X] Could not find code for {name} @ {addr}")
            continue
        
        code = match.group(1).strip()

        prompt = f"""
        Analyze this function from a reverse engineering project. 
        It was flagged as potential boilerplate (compiler/runtime code).
        
        Function Name: {name}
        Address: {addr}
        Code:
        {code}

        Is this standard library/compiler boilerplate (like MinGW, CRT, or basic API wrappers) 
        or is it specific application logic (like game rules or user behavior)?

        Response format:
        TYPE: [BOILERPLATE or APPLICATION]
        NEW_NAME: [If APPLICATION, provide a descriptive name. If BOILERPLATE, keep original]
        REASON: [Short justification]
        """

        try:
            # Using the 2.0 Flash model for fast verification
            response = client.models.generate_content(
                model="gemini-3-flash-preview", 
                contents=prompt
            )
            
            res_text = response.text
            is_app = "TYPE: APPLICATION" in res_text
            
            if is_app:
                # Extract the proposed name
                new_name_match = re.search(r"NEW_NAME:\s*(.*)", res_text)
                new_name = new_name_match.group(1).strip() if new_name_match else "RenamingError"
                print(f"    [!] {addr} ({name}) is APPLICATION LOGIC. Proposed: {new_name}")
            else:
                print(f"    [-] {addr} ({name}) confirmed as BOILERPLATE.")
                
        except Exception as e:
            print(f"    [X] Error analyzing {name}: {e}")

    print(f"\n[+] Verification complete.")

if __name__ == "__main__":
    verify_and_rename()