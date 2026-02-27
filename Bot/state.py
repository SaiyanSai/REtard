import operator
from typing import TypedDict, List, Dict, Annotated

class REState(TypedDict):
    functions: Dict[str, dict]
    symbol_table: Dict[str, str]
    current_target: str
    suggested_target: str 
    call_graph: Dict[str, List[str]]
    history: Annotated[List[str], operator.add]
    phase: str