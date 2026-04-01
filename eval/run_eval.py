#!/usr/bin/env python3
"""
run_eval.py  –  REtard Automated Evaluation Framework
======================================================

Usage
-----
    python run_eval.py path/to/target.c [options]

What it does
------------
  1. Compile target.c two ways:
       • debug   (-g -O0 -no-pie)        → DWARF symbols intact
       • stripped (-O0 -no-pie + strip)  → symbol-free binary

  2. Decompile both with Ghidra headless using GhidraExport.java
       • debug_decompiled.c   → Ghidra shows real names (ground truth)
       • stripped_decompiled.c → Ghidra shows FUN_xxx / uVar placeholders

  3. Extract ground truth
       • Parse original source file       → authoritative names
       • Parse debug_decompiled.c         → "what Ghidra can see"
       • Merge into unified GroundTruth

  4. Run the REtard agent on the stripped decompilation
       • Copies Bot/ into an isolated workspace
       • Patches config to point at the eval files
       • Runs main_eval.py (the LangGraph pipeline)
       • Reads analysis_state.json after completion

  5. Evaluate
       • Compare symbol_table ↔ ground truth
       • Score at exact / normalised / fuzzy / partial tiers
       • Compute Precision, Recall, F1, Coverage

  6. Report
       • eval/eval_report.json  – machine-readable
       • eval/eval_report.html  – rich interactive HTML

Prerequisites
-------------
  • GCC + strip     (apt install build-essential)
  • Ghidra ≥ 10     (set GHIDRA_PATH in .env or environment)
  • GEMINI_API_KEY  (set in .env)
  • All Python deps from Bot/requirments.txt
      pip install -r Bot/requirments.txt

Options
-------
  --skip-compile      Skip compilation (use existing workspace/target_*)
  --skip-decompile    Skip Ghidra (use existing workspace/*_decompiled.c)
  --skip-agent        Skip running the agent (use existing analysis_state.json)
  --workspace DIR     Custom workspace dir (default: eval/workspace/)
  --python  PATH      Python interpreter for running the agent
  --report-only       Only (re-)generate reports from existing JSON
"""

import argparse
import json
import sys
import os
from pathlib import Path

# Add eval/ to path so imports work when called from any working directory
_EVAL_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_EVAL_DIR))

from eval_config    import GHIDRA_PATH, EVAL_WORKSPACE, DEBUG_BIN_NAME, STRIP_BIN_NAME
from compile_targets import compile_both
from ghidra_decompile import decompile_both
from ground_truth    import (
    extract_from_source, extract_from_debug_decompiled,
    merge_ground_truths, ground_truth_to_dict,
)
from agent_runner    import run_agent
from evaluator       import evaluate
from report_generator import save_json_report, save_html_report


# ─────────────────────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────────────────────

BANNER = r"""
 ____  _____  _                    _   _____            _
|  _ \| ____|| |_  __ _  _ __  __| | | ____|__   ____ | |
| |_) |  _|  | __|/ _` || '__|/ _` | |  _|  \ \ / / _` | |
|  _ < | |___| |_| (_| || |  | (_| | | |___  \ V / (_| | |
|_| \_\|_____|\__|\__,_||_|   \__,_| |_____|  \_/ \__,_|_|

       Automated Reverse-Engineering Evaluation Framework
"""


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="REtard automated evaluation framework.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("source_file", help="Path to the .c file to evaluate against")
    p.add_argument("--skip-compile",    action="store_true", help="Reuse existing compiled binaries")
    p.add_argument("--skip-decompile",  action="store_true", help="Reuse existing Ghidra decompilations")
    p.add_argument("--skip-agent",      action="store_true", help="Reuse existing agent analysis_state.json")
    p.add_argument("--report-only",     action="store_true", help="Re-run reporting from cached eval_results.json")
    p.add_argument("--workspace",       default=str(EVAL_WORKSPACE), help="Workspace directory")
    p.add_argument("--python",          default=sys.executable, help="Python interpreter for agent")
    return p.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# Step implementations
# ─────────────────────────────────────────────────────────────────────────────

def _step_compile(source_file: Path, workspace: Path, skip: bool) -> tuple[Path, Path]:
    debug_bin    = workspace / DEBUG_BIN_NAME
    stripped_bin = workspace / STRIP_BIN_NAME

    if skip and debug_bin.exists() and stripped_bin.exists():
        print("[step 1/6] SKIP – using existing binaries")
        return debug_bin, stripped_bin

    print("\n" + "="*60)
    print("[step 1/6] COMPILE – building debug and stripped binaries")
    print("="*60)
    return compile_both(source_file, workspace, DEBUG_BIN_NAME, STRIP_BIN_NAME)


def _step_decompile(
    debug_bin: Path, stripped_bin: Path, workspace: Path,
    ghidra_path: str, skip: bool,
) -> tuple[Path, Path]:
    debug_c    = workspace / "debug_decompiled.c"
    stripped_c = workspace / "stripped_decompiled.c"

    if skip and debug_c.exists() and stripped_c.exists():
        print("[step 2/6] SKIP – using existing decompilations")
        return debug_c, stripped_c

    print("\n" + "="*60)
    print("[step 2/6] DECOMPILE – running Ghidra headless")
    print("="*60)
    return decompile_both(debug_bin, stripped_bin, workspace, ghidra_path)


def _step_ground_truth(
    source_file: Path, debug_c: Path, workspace: Path,
) -> dict:
    gt_cache = workspace / "ground_truth.json"

    print("\n" + "="*60)
    print("[step 3/6] GROUND TRUTH – extracting names")
    print("="*60)

    src_gt   = extract_from_source(source_file)
    debug_gt = extract_from_debug_decompiled(debug_c)
    merged   = merge_ground_truths(src_gt, debug_gt)

    gt_dict = ground_truth_to_dict(merged)
    gt_cache.write_text(json.dumps(gt_dict, indent=2))
    print(f"[ground_truth] Saved to {gt_cache}")

    return merged


def _step_run_agent(
    workspace: Path, stripped_bin: Path, stripped_c: Path,
    python_exe: str, skip: bool,
) -> dict:
    state_cache = workspace / "agent_bot" / "analysis_state.json"

    if skip and state_cache.exists():
        print("[step 4/6] SKIP – using existing agent state")
        with open(state_cache) as f:
            return json.load(f)

    print("\n" + "="*60)
    print("[step 4/6] AGENT – running REtard reverse-engineering agent")
    print("="*60)
    return run_agent(workspace, stripped_bin, stripped_c, python_exe)


def _step_evaluate(gt, agent_output: dict, workspace: Path) -> "EvalResults":  # type: ignore
    from evaluator import evaluate, EvalResults

    print("\n" + "="*60)
    print("[step 5/6] EVALUATE – comparing recovered names to ground truth")
    print("="*60)

    results = evaluate(gt, agent_output)

    # Cache raw results
    results_cache = workspace / "eval_results.json"
    results_cache.write_text(json.dumps(results.to_dict(), indent=2))

    # Print summary
    s = results.to_dict()["summary"]
    fn = results.to_dict()["function_recovery"]["metrics"]["any"]
    vr = results.to_dict()["variable_recovery"]["metrics"]["any"]

    print(f"\n{'─'*50}")
    print(f"  Ground truth : {s['gt_functions']} functions, {s['gt_variables']} variables")
    print(f"  Agent renamed: {s['agent_function_renames']} functions, {s['agent_variable_renames']} variables")
    print(f"")
    print(f"  Function F1  : {fn['f1']:.1%}  (P={fn['precision']:.1%}, R={fn['recall']:.1%})")
    print(f"  Variable F1  : {vr['f1']:.1%}  (P={vr['precision']:.1%}, R={vr['recall']:.1%})")
    print(f"  Overall Score: {s['overall_score']:.1%}")
    print(f"{'─'*50}\n")

    return results


def _step_report(results, source_file: str, workspace: Path) -> None:
    print("\n" + "="*60)
    print("[step 6/6] REPORT – generating JSON + HTML reports")
    print("="*60)

    json_path = _EVAL_DIR / "eval_report.json"
    html_path = _EVAL_DIR / "eval_report.html"

    save_json_report(results, json_path)
    save_html_report(results, html_path, source_file=str(source_file))

    print(f"\n✔  Evaluation complete.")
    print(f"   JSON : {json_path}")
    print(f"   HTML : {html_path}")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print(BANNER)
    args = parse_args()

    source_file = Path(args.source_file).resolve()
    if not source_file.exists():
        print(f"[ERROR] Source file not found: {source_file}")
        sys.exit(1)
    if source_file.suffix.lower() != ".c":
        print(f"[WARNING] Expected a .c file but got: {source_file.suffix}")

    workspace = Path(args.workspace).resolve()
    workspace.mkdir(parents=True, exist_ok=True)

    # ── --report-only mode ────────────────────────────────────────────────────
    if args.report_only:
        results_cache = workspace / "eval_results.json"
        if not results_cache.exists():
            print(f"[ERROR] No cached eval_results.json at {results_cache}. "
                  "Run without --report-only first.")
            sys.exit(1)
        # Reconstruct a lightweight EvalResults for reporting only
        from evaluator import EvalResults
        import json as _json
        with open(results_cache) as f:
            raw = _json.load(f)
        _step_report_from_dict(raw, str(source_file))
        return

    # ── Normal pipeline ───────────────────────────────────────────────────────
    debug_bin, stripped_bin = _step_compile(
        source_file, workspace, skip=args.skip_compile)

    debug_c, stripped_c = _step_decompile(
        debug_bin, stripped_bin, workspace,
        ghidra_path=GHIDRA_PATH, skip=args.skip_decompile)

    gt = _step_ground_truth(source_file, debug_c, workspace)

    agent_output = _step_run_agent(
        workspace, stripped_bin, stripped_c,
        python_exe=args.python, skip=args.skip_agent)

    results = _step_evaluate(gt, agent_output, workspace)

    _step_report(results, str(source_file), workspace)


def _step_report_from_dict(raw: dict, source_file: str):
    """Minimal re-report path when only raw JSON is available."""
    from report_generator import save_html_report, save_json_report
    from evaluator import EvalResults, TierCounts, MetricSet, NameMatch

    def _ms(d):
        return MetricSet(
            precision=d["precision"], recall=d["recall"],
            f1=d["f1"], coverage=d["coverage"],
        )
    def _tc(d):
        return TierCounts(
            exact=d["exact"], normalised=d["normalised"], fuzzy=d["fuzzy"],
            partial=d.get("partial", 0), no_match=d["no_match"],
        )
    def _nm_list(lst):
        return [NameMatch(
            original_key=m["placeholder"],
            recovered_name=m["recovered"],
            match_tier=m["tier"],
            closest_gt_name=m.get("closest_gt"),
            similarity=m.get("similarity", 0.0),
        ) for m in lst]

    fn_r  = raw["function_recovery"]
    vr_r  = raw["variable_recovery"]
    summ  = raw["summary"]
    results = EvalResults(
        gt_function_count      = summ["gt_functions"],
        gt_variable_count      = summ["gt_variables"],
        agent_function_renames = summ["agent_function_renames"],
        agent_variable_renames = summ["agent_variable_renames"],
        function_matches       = _nm_list(fn_r["matches"]),
        function_tiers         = _tc(fn_r["tiers"]),
        function_metrics       = {k: _ms(v) for k, v in fn_r["metrics"].items()},
        variable_matches       = _nm_list(vr_r["matches"]),
        variable_tiers         = _tc(vr_r["tiers"]),
        variable_metrics       = {k: _ms(v) for k, v in vr_r["metrics"].items()},
        per_function           = raw.get("per_function", {}),
        overall_score          = summ["overall_score"],
    )
    json_path = _EVAL_DIR / "eval_report.json"
    html_path = _EVAL_DIR / "eval_report.html"
    save_json_report(results, json_path)
    save_html_report(results, html_path, source_file=source_file)
    print(f"✔  Reports regenerated.\n   JSON: {json_path}\n   HTML: {html_path}")


if __name__ == "__main__":
    main()
