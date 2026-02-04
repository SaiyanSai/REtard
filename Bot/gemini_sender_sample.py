import os
import re
from pathlib import Path
from google import genai
from tabulate import tabulate
from httpx import Timeout

# --- CONFIGURATION ---
API_KEY = "REDACTED"
client = genai.Client(api_key=API_KEY)

INPUT_C = "/home/saiyansai/RE/Bot/decompiled_output.c"
OUTPUT_REPORT = "/home/saiyansai/RE/Bot/gemini_analysis.txt"

def analyze_decompiled_code():
    if not Path(INPUT_C).exists():
        print(f"[!] Error: {INPUT_C} not found. Run the Ghidra script first.")
        return

    with open(INPUT_C, "r") as f:
        content = f.read()

    # Regex to extract: [Name, Address, Body]
    pattern = r"// --- Function: (.*?) @ (.*?) ---\n(.*?)(?=\n// --- Function:|\Z)"
    matches = re.findall(pattern, content, re.DOTALL)

    if not matches:
        print("[!] No functions found. Ensure the decompiler script ran correctly.")
        return

    analysis_results = []
    
    # Process only the first 5 functions
    for i, (name, addr, code) in enumerate(matches[:5]):
        print(f"[*] Analyzing function {i+1}/5: {name}")
        
        prompt = f"""
        Analyze this decompiled C function for a reverse engineering project.
        Function Name: {name}
        
        Code:
        {code.strip()}
        
        Return the analysis in the following strict format:
        PROPOSED_NAME: [Better name for this function]
        VARIABLES: [Map generic variables to their purpose]
        SUMMARY: [Concise logic explanation]
        """

        try:
            # Using the modern SDK and Flash model for logic mapping
            response = client.models.generate_content(
                model="gemini-3-flash-preview", 
                contents=prompt,
                config={'http_options': Timeout(60.0, connect=30.0)}
            )
            
            raw_text = response.text
            
            # Parse Gemini's response for the table
            new_name = "Unknown"
            variables = "N/A"
            summary = "N/A"

            if "PROPOSED_NAME:" in raw_text:
                new_name = raw_text.split("PROPOSED_NAME:")[1].split("VARIABLES:")[0].strip()
            if "VARIABLES:" in raw_text:
                variables = raw_text.split("VARIABLES:")[1].split("SUMMARY:")[0].strip()
            if "SUMMARY:" in raw_text:
                summary = raw_text.split("SUMMARY:")[1].strip()
            
            analysis_results.append([name, new_name, variables, summary])
            
        except Exception as e:
            analysis_results.append([name, "Error", str(e), "N/A"])

    # --- OUTPUT GENERATION ---
    headers = ["Original Name", "Proposed New Name", "Variable Inferences", "Logic Summary"]
    table_output = tabulate(analysis_results, headers=headers, tablefmt="grid")

    print("\n" + table_output)

    with open(OUTPUT_REPORT, "w") as f:
        f.write("REVERSE ENGINEERING ANALYSIS REPORT\n")
        f.write("="*60 + "\n\n")
        f.write(table_output)
    
    print(f"\n[+] Analysis complete. Report saved to: {OUTPUT_REPORT}")

if __name__ == "__main__":
    analyze_decompiled_code()