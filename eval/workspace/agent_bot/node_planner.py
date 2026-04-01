from state import REState
from tqdm import tqdm
from utils import save_json_state

def planner_node(state: REState):
    funcs = state["functions"]
    
    save_json_state(state)
    
    suggested = state.get("suggested_target")
    if suggested and suggested in funcs and funcs[suggested]["status"] == "PENDING":
        tqdm.write(f"[*] Following LLM breadcrumb: {suggested}")
        return {"current_target": suggested, "phase": "analysis_loop", "history": []}
    
    pending = [(n, d) for n, d in funcs.items() if d["status"] == "PENDING"]
    if pending:
        best_func = max(pending, key=lambda x: x[1].get("string_score", 0))[0]
        tqdm.write(f"[*] Anchoring to top priority function: {best_func} (Score: {funcs[best_func].get('string_score', 0)})")
        return {"current_target": best_func, "phase": "analysis_loop", "suggested_target": "", "history": []}
    
    partials = [(n, d) for n, d in funcs.items() if d["status"] == "PARTIAL"]
    if partials:
        target = partials[0][0]
        tqdm.write(f"[*] Re-evaluating partial function: {target}")
        return {"current_target": target, "phase": "revisit", "suggested_target": "", "history": []}
        
    partial_ends = [(n, d) for n, d in funcs.items() if d["status"] == "PARTIAL_END"]
    if partial_ends:
        target = partial_ends[0][0]
        tqdm.write(f"[*] Final Sweep: {target}")
        return {"current_target": target, "phase": "final_sweep", "suggested_target": "", "history": []}

    return {"phase": "end", "history": ["Analysis Complete."]}