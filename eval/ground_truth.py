"""
ground_truth.py  –  Extract ground-truth names from two sources.
"""

import re
from pathlib import Path
from typing import NamedTuple

# ─────────────────────────────────────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────────────────────────────────────

class FunctionGT(NamedTuple):
    name:       str               
    params:     list[str]         
    locals:     list[str]         
    all_names:  set[str]          

class GroundTruth(NamedTuple):
    functions:          dict[str, FunctionGT]  
    all_function_names: set[str]
    all_variable_names: set[str]               

# ─────────────────────────────────────────────────────────────────────────────
# C source parser
# ─────────────────────────────────────────────────────────────────────────────

_C_TYPES = (
    r"void|int|long|short|char|float|double|unsigned|signed|"
    r"size_t|ssize_t|uint8_t|uint16_t|uint32_t|uint64_t|"
    r"int8_t|int16_t|int32_t|int64_t|bool|_Bool|"
    r"struct|enum|union"
)

_KEYWORDS = frozenset(
    "if else for while do switch case default break continue return "
    "goto sizeof typeof NULL true false typedef extern static inline "
    "register volatile const restrict".split()
)

# FIXED: Boilerplate functions that shouldn't be scored against the agent
_BOILERPLATE = frozenset([
    "_init", "_fini", "_start", "__libc_csu_init", "__libc_csu_fini",
    "__libc_start_main", "__cxa_finalize", "__gmon_start__",
    "deregister_tm_clones", "register_tm_clones", "__do_global_dtors_aux",
    "frame_dummy", "printf", "puts", "strncpy", "strcpy", "strlen", "malloc", 
    "free", "exit", "scanf"
])

_PLACEHOLDER_RE = re.compile(
    r"^(uVar|iVar|lVar|pcVar|pvVar|bVar|dVar|"
    r"local_|param_|DAT_|FUN_|PTR_|WORD_|DWORD_|BYTE_|"
    r"extraout_|in_)\d"
)

def _strip_comments(code: str) -> str:
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)
    code = re.sub(r"//[^\n]*", "", code)
    return code

def _extract_identifier(raw: str) -> str | None:
    name = re.sub(r"^[\s\*]+", "", raw).strip()
    name = re.sub(r"\[.*", "", name).strip()
    name = re.sub(r"\(.*", "", name).strip()   
    if not re.match(r"^[a-zA-Z_]\w*$", name):
        return None
    if name in _KEYWORDS or re.match(_PLACEHOLDER_RE, name):
        return None
    return name

def _parse_param_list(param_str: str) -> list[str]:
    if not param_str.strip() or param_str.strip() in ("void", "..."):
        return []
    names: list[str] = []
    for param in param_str.split(","):
        param = param.strip()
        tokens = re.split(r"\s+", param)
        for tok in reversed(tokens):
            ident = _extract_identifier(tok)
            if ident:
                names.append(ident)
                break
    return names

def _parse_local_variables(body: str) -> list[str]:
    body = re.sub(r'"[^"\\]*(?:\\.[^"\\]*)*"', '""', body)
    names: list[str] = []
    decl_pattern = re.compile(
        rf"^\s*(?:(?:static|extern|register|volatile|const|inline|unsigned|signed|long|short)\s+)*"
        rf"(?:{_C_TYPES})\s*\**\s*"
        rf"([a-zA-Z_]\w*)"          
        rf"((?:\s*,\s*\**\s*[a-zA-Z_]\w*)*)"  
        rf"(?:\s*=|\s*;|\s*\[)",
        re.MULTILINE,
    )
    for m in decl_pattern.finditer(body):
        first = _extract_identifier(m.group(1))
        if first:
            names.append(first)
        for extra in re.findall(r",\s*\**\s*([a-zA-Z_]\w*)", m.group(2) or ""):
            ident = _extract_identifier(extra)
            if ident:
                names.append(ident)
    return list(dict.fromkeys(names))  

def _split_into_functions(code: str) -> list[tuple[str, str, str]]:
    func_open = re.compile(
        r"^(?:(?:static|extern|inline|__attribute__\s*\(\(.*?\)\))\s+)*"
        r"(?:[\w\*\s]+?)\s+"           
        r"(\w+)"                        
        r"\s*\(([^)]*)\)"              
        r"\s*\{",                       
        re.MULTILINE,
    )
    results: list[tuple[str, str, str]] = []
    for m in func_open.finditer(code):
        func_name = m.group(1)
        param_str = m.group(2)
        
        # FIXED: Ignore keywords and standard compiler boilerplate
        if func_name in _KEYWORDS or func_name in _BOILERPLATE or func_name.startswith("__x86"):
            continue

        start = m.end()  
        depth = 1
        i = start
        while i < len(code) and depth > 0:
            if code[i] == "{":
                depth += 1
            elif code[i] == "}":
                depth -= 1
            i += 1
        body = code[start : i - 1]
        results.append((func_name, param_str, body))
    return results

def extract_from_source(source_file: str | Path) -> GroundTruth:
    code = Path(source_file).read_text(encoding="utf-8", errors="replace")
    code = _strip_comments(code)
    functions: dict[str, FunctionGT] = {}
    for func_name, param_str, body in _split_into_functions(code):
        params = _parse_param_list(param_str)
        locals_ = _parse_local_variables(body)
        all_names = set(params) | set(locals_)
        functions[func_name] = FunctionGT(func_name, params, locals_, all_names)

    all_func_names = set(functions.keys())
    all_var_names  = set()
    for fgt in functions.values():
        all_var_names |= fgt.all_names

    print(f"[ground_truth] Source: {len(all_func_names)} functions, "
          f"{len(all_var_names)} unique variable names")
    return GroundTruth(functions, all_func_names, all_var_names)

def extract_from_debug_decompiled(debug_c: str | Path) -> GroundTruth:
    content = Path(debug_c).read_text(encoding="utf-8", errors="replace")
    section_re = re.compile(
        r"// --- Function: (\S+) @ [0-9a-fA-F]+ ---\n(.*?)(?=\n// --- Function:|\Z)",
        re.DOTALL,
    )
    functions: dict[str, FunctionGT] = {}
    for m in section_re.finditer(content):
        raw_name = m.group(1).strip()
        body     = m.group(2)

        if re.match(_PLACEHOLDER_RE, raw_name):
            continue
            
        # FIXED: Ignore keywords and standard compiler boilerplate
        if raw_name in _KEYWORDS or raw_name in _BOILERPLATE or raw_name.startswith("__x86"):
            continue

        sig_line = ""
        for line in body.splitlines():
            if line.strip() and not line.strip().startswith("//"):
                sig_line = line
                break

        param_match = re.search(r"\(([^)]*)\)", sig_line)
        params = _parse_param_list(param_match.group(1)) if param_match else []
        locals_ = _parse_local_variables(body)

        params  = [p for p in params  if not re.match(_PLACEHOLDER_RE, p) and p not in _KEYWORDS]
        locals_ = [l for l in locals_ if not re.match(_PLACEHOLDER_RE, l) and l not in _KEYWORDS]

        all_names = set(params) | set(locals_)
        functions[raw_name] = FunctionGT(raw_name, params, locals_, all_names)

    all_func_names = set(functions.keys())
    all_var_names  = set()
    for fgt in functions.values():
        all_var_names |= fgt.all_names

    print(f"[ground_truth] Debug-decompiled: {len(all_func_names)} functions, "
          f"{len(all_var_names)} unique variable names")
    return GroundTruth(functions, all_func_names, all_var_names)

def merge_ground_truths(source_gt: GroundTruth, debug_gt: GroundTruth) -> GroundTruth:
    merged_functions: dict[str, FunctionGT] = {}
    all_names = source_gt.all_function_names | debug_gt.all_function_names
    for fname in all_names:
        src_fgt  = source_gt.functions.get(fname)
        dbg_fgt  = debug_gt.functions.get(fname)
        if src_fgt and dbg_fgt:
            params  = list(dict.fromkeys(src_fgt.params  + dbg_fgt.params))
            locals_ = list(dict.fromkeys(src_fgt.locals  + dbg_fgt.locals))
        elif src_fgt:
            params, locals_ = src_fgt.params, src_fgt.locals
        else:
            params, locals_ = dbg_fgt.params, dbg_fgt.locals  
        all_n = set(params) | set(locals_)
        merged_functions[fname] = FunctionGT(fname, params, locals_, all_n)

    all_func_names = set(merged_functions.keys())
    all_var_names  = set()
    for fgt in merged_functions.values():
        all_var_names |= fgt.all_names

    print(f"[ground_truth] Merged: {len(all_func_names)} functions, "
          f"{len(all_var_names)} unique variable names")
    return GroundTruth(merged_functions, all_func_names, all_var_names)

def ground_truth_to_dict(gt: GroundTruth) -> dict:
    return {
        "all_function_names": sorted(gt.all_function_names),
        "all_variable_names": sorted(gt.all_variable_names),
        "functions": {
            fname: { "params":  fgt.params, "locals":  fgt.locals }
            for fname, fgt in gt.functions.items()
        },
    }