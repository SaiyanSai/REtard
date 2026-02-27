from tqdm import tqdm
from state import REState
from utils import save_json_state

def planner_node(state: REState):
    save_json_state(state)
    f = state["functions"]
    pending = [n for n in f if f[n]["status"] == "PENDING"]
    partial = [n for n in f if f[n]["status"] == "PARTIAL"]
    p_end = [n for n in f if f[n]["status"] == "PARTIAL_END"]
    
    if not pending and not partial and not p_end:
        return {"phase": "end", "current_target": None}

    sug = state.get("suggested_target")
    if sug and sug in pending:
        tqdm.write(f"[*] Following LLM breadcrumb: {sug}")
        return {"current_target": sug, "phase": "analysis_loop", "suggested_target": ""}

    if partial:
        tqdm.write(f"[*] Trail ended. Re-evaluating partial function: {partial[0]}")
        return {"current_target": partial[0], "phase": "revisit", "suggested_target": ""}

    wrappers = [n for n in pending if f[n]["is_wrapper"]]
    if wrappers:
        return {"current_target": sorted(wrappers)[0], "phase": "analysis_loop", "suggested_target": ""}

    if pending:
        target = max(pending, key=lambda n: f[n]["string_score"])
        tqdm.write(f"[*] Suggestion chain end. Anchoring to top priority function: {target} (Score: {f[target]['string_score']})")
        return {"current_target": target, "phase": "analysis_loop", "suggested_target": ""}

    if p_end:
        if state["phase"] != "final_sweep":
            print("\n" + "="*30 + "\n[PHASE: FINAL SWEEP - RESOLVING STUBBORN FUNCTIONS]\n" + "="*30)
        return {"current_target": p_end[0], "phase": "final_sweep", "suggested_target": ""}

    return {"phase": "end", "current_target": None}