# REtard Evaluation Framework

Automated pipeline to measure how accurately the REtard LLM agent recovers
variable and function names from stripped binaries.

```
input.c ──┬──► gcc -g -O0 ──► debug.elf ──► Ghidra ──► debug_decompiled.c ──► GROUND TRUTH
           │
           └──► gcc -O0 + strip ──► stripped.elf ──► Ghidra ──► stripped_decompiled.c
                                                                          │
                                                              REtard Agent (Gemini)
                                                                          │
                                                               analysis_state.json
                                                                          │
                                                          ┌───────────────▼───────────────┐
                                                          │   EVALUATOR: compare names    │
                                                          │   Exact / Normalised / Fuzzy  │
                                                          │   Precision · Recall · F1     │
                                                          └───────────┬───────────────────┘
                                                                      │
                                                         eval_report.html + eval_report.json
```

---

## Prerequisites

| Tool | Install |
|------|---------|
| GCC + strip | `sudo apt install build-essential` |
| Ghidra ≥ 10 | [ghidra.re](https://ghidra-sre.org/) |
| Python ≥ 3.11 | system or venv |
| REtard Bot deps | `pip install -r Bot/requirments.txt` |
| GEMINI_API_KEY | add to `.env` in project root |
| GHIDRA_PATH | add to `.env` (see below) |

**.env example**
```
GEMINI_API_KEY=AIza...
GHIDRA_PATH=/opt/ghidra_11.2_PUBLIC/support/analyzeHeadless
```

---

## Quick Start

```bash
# From REtard-main/ root
python eval/run_eval.py path/to/target.c
```

Open `eval/eval_report.html` in a browser when done.

---

## Command-line options

```
usage: run_eval.py source_file [options]

positional arguments:
  source_file          Path to the .c file to evaluate against

options:
  --skip-compile       Reuse existing compiled binaries in workspace/
  --skip-decompile     Reuse existing Ghidra decompilations in workspace/
  --skip-agent         Reuse existing agent analysis_state.json
  --report-only        Re-generate reports from cached eval_results.json
  --workspace DIR      Custom workspace directory (default: eval/workspace/)
  --python PATH        Python interpreter for running the agent
```

### Useful combos

```bash
# Run everything fresh
python eval/run_eval.py src/crackme.c

# Skip expensive Ghidra re-run (binary hasn't changed)
python eval/run_eval.py src/crackme.c --skip-compile --skip-decompile

# Only regenerate the HTML report (evaluation already done)
python eval/run_eval.py src/crackme.c --report-only
```

---

## Output files

| File | Description |
|------|-------------|
| `eval/workspace/target_debug` | Debug ELF with DWARF symbols |
| `eval/workspace/target_stripped` | Stripped ELF (no symbols) |
| `eval/workspace/debug_decompiled.c` | Ghidra output for debug binary |
| `eval/workspace/stripped_decompiled.c` | Ghidra output for stripped binary |
| `eval/workspace/ground_truth.json` | Merged ground-truth names |
| `eval/workspace/agent_bot/analysis_state.json` | Agent's final state |
| `eval/eval_report.json` | Machine-readable evaluation results |
| `eval/eval_report.html` | **Human-readable HTML report** |

---

## Evaluation metrics

### Match tiers (strictest → most lenient)

| Tier | Rule |
|------|------|
| **Exact** | `recovered == gt_name` (case-sensitive) |
| **Normalised** | lower-case + strip underscores match (`calcSum` ≡ `calc_sum`) |
| **Fuzzy** | Levenshtein similarity ≥ 0.70 |
| **Partial** | (functions only) one name is a substring of the other |

### Scores

For each tier, the framework computes:

- **Precision** – of all names the agent proposed, what fraction match GT?
- **Recall** – of all GT names, what fraction did the agent recover?
- **F1** – harmonic mean of precision and recall
- **Coverage** – what fraction of GT items did the agent *attempt* to rename?

### Overall score

```
Overall = 0.40 × Function_F1_any  +  0.60 × Variable_F1_any
```

Variables are weighted higher because there are typically many more of them
and recovering them represents a larger fraction of the analyst's work.

---

## How it works internally

### Ground truth extraction

1. **Source parser** (`ground_truth.py::extract_from_source`)
   - Regex-based C parser: finds function definitions via brace matching
   - Extracts: function names, parameter names, local variable declarations
   - Filters out C keywords and Ghidra-style placeholder names

2. **Debug-decompiled parser** (`ground_truth.py::extract_from_debug_decompiled`)
   - Reads Ghidra's output for the debug binary
   - When DWARF is available, Ghidra uses the original names directly
   - This gives us "what Ghidra can actually see" – the fairest target

3. **Merge** – union of both sets; source wins on conflicts

### Agent isolation

The framework copies `Bot/` into `workspace/agent_bot/` and overwrites
`config.py` with paths that point at the eval workspace.  A unique
`thread_id` is generated per run to prevent LangGraph checkpoint collisions.

### Scoring

Implemented entirely in `evaluator.py` with no AI calls – pure
string-similarity algorithms (Levenshtein, substring check, normalisation).
