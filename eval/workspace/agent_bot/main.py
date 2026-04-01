import sys
import argparse
from pathlib import Path

sys.path.append(str(Path(__file__).parent))

# 1. Parse arguments FIRST before importing anything that depends on config
parser = argparse.ArgumentParser(description="REtard Analysis Bot")
parser.add_argument("-t", "--target", type=str, help="Path to the target binary")
parser.add_argument("--thread", type=str, help="Optional thread ID for the checkpoint")
args, _ = parser.parse_known_args()

# 2. Import config and override TARGET_BINARY if the argument was provided
import config
if args.target:
    config.TARGET_BINARY = args.target

# 3. Now safely import the rest of the graph components
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.sqlite import SqliteSaver
from tqdm import tqdm

from state import REState
from node_ingestion import ingestion_node
from node_triage import triage_node
from node_planner import planner_node
from node_analyst import analyst_node
from node_dynamic import dynamic_node 

builder = StateGraph(REState)
builder.add_node("ingestor", ingestion_node)
builder.add_node("triager", triage_node)
builder.add_node("planner", planner_node)
builder.add_node("analyst", analyst_node)
builder.add_node("dynamic", dynamic_node)

builder.set_entry_point("ingestor")
builder.add_edge("ingestor", "triager")
builder.add_edge("triager", "planner")

def analyst_router(state: REState):
    target = state["current_target"]
    if state["functions"][target]["status"] == "OBFUSCATED":
        return "dynamic"
    return "planner"

builder.add_conditional_edges("analyst", analyst_router, {"dynamic": "dynamic", "planner": "planner"})
builder.add_edge("dynamic", "planner")
builder.add_conditional_edges("planner", lambda x: "end" if x["phase"] == "end" else "continue", {"end": END, "continue": "analyst"})

if __name__ == "__main__":
    with SqliteSaver.from_conn_string(config.CHECKPOINT_DB) as saver:
        graph = builder.compile(checkpointer=saver)
        
        # Fresh start - Dynamically generate thread_id based on binary name if not provided
        binary_name = Path(config.TARGET_BINARY).stem
        thread_id = args.thread if args.thread else f"{binary_name}_analysis"
        run_config = {"configurable": {"thread_id": thread_id}} 
        
        initial_state = {
            "functions": {}, "symbol_table": {}, "current_target": "", 
            "suggested_target": "", "call_graph": {}, "history": [], "phase": "start"
        }
        
        print(f"[*] Starting analysis on: {config.TARGET_BINARY} (Thread ID: {thread_id})")
        
        pbar = None
        for event in graph.stream(initial_state, config=run_config):
            for node, output in event.items():
                if node == "ingestor" and not pbar:
                    pbar = tqdm(total=len(output["functions"]), initial=len(output["symbol_table"]), desc="Total Progress")
                if node in ["analyst", "dynamic"] and pbar and any(s in h for h in output.get("history", []) for s in ["ANALYZED", "deobfuscated"]):
                    pbar.update(1)
                if output.get("history"): 
                    tqdm.write(f"[{node.upper()}] {output['history'][-1]}")
        
        if pbar: pbar.close()