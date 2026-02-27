import sys
from pathlib import Path

# Ensure imports resolve correctly from Bot/
sys.path.append(str(Path(__file__).parent))

from langgraph.graph import StateGraph, END
from langgraph.checkpoint.sqlite import SqliteSaver
from tqdm import tqdm

from config import CHECKPOINT_DB
from state import REState
from node_ingestion import ingestion_node
from node_triage import triage_node
from node_planner import planner_node
from node_analyst import analyst_node

# --- GRAPH CONSTRUCTION ---
builder = StateGraph(REState)
builder.add_node("ingestor", ingestion_node)
builder.add_node("triager", triage_node)
builder.add_node("planner", planner_node)
builder.add_node("analyst", analyst_node)

builder.set_entry_point("ingestor")
builder.add_edge("ingestor", "triager")
builder.add_edge("triager", "planner")
builder.add_edge("analyst", "planner")
builder.add_conditional_edges("planner", lambda x: "end" if x["phase"] == "end" else "continue", {"end": END, "continue": "analyst"})

if __name__ == "__main__":
    with SqliteSaver.from_conn_string(CHECKPOINT_DB) as saver:
        graph = builder.compile(checkpointer=saver)
        config = {"configurable": {"thread_id": "spider_v12"}}
        
        initial_state = {
            "functions": {}, "symbol_table": {}, "current_target": "", 
            "suggested_target": "", "call_graph": {}, "history": [], "phase": "start"
        }
        
        pbar = None
        for event in graph.stream(initial_state, config=config):
            for node, output in event.items():
                if node == "ingestor" and not pbar:
                    pbar = tqdm(total=len(output["functions"]), initial=len(output["symbol_table"]), desc="Total Progress")
                if node == "analyst" and pbar and any("ANALYZED" in h for h in output.get("history", [])):
                    pbar.update(1)
                if "history" in output: 
                    tqdm.write(f"[{node.upper()}] {output['history'][-1]}")
        
        if pbar: pbar.close()