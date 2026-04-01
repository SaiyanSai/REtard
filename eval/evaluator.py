"""
evaluator.py  –  Compare the REtard agent's recovered names against ground truth.
"""

import re
import os
from dataclasses import dataclass, field
from typing import Optional
from ground_truth import GroundTruth
from eval_config import FUZZY_MATCH_THRESHOLD, USE_LLM_JUDGE

# ─────────────────────────────────────────────────────────────────────────────
# LLM Judge Setup
# ─────────────────────────────────────────────────────────────────────────────
llm_client = None
if USE_LLM_JUDGE:
    from google import genai
    api_key = os.environ.get("GEMINI_API_KEY")
    if api_key:
        llm_client = genai.Client(api_key=api_key)
    else:
        print("[evaluator] WARNING: GEMINI_API_KEY not found, LLM judge disabled.")

def _semantic_match(recovered: str, closest_gt: str) -> bool:
    """Uses LLM to check if two variable/function names mean the same thing."""
    if not llm_client or not closest_gt: return False
    prompt = f"In the context of reverse engineering C code, are the names '{recovered}' and '{closest_gt}' semantically equivalent or referring to the exact same concept? Reply only with YES or NO."
    try:
        resp = llm_client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt
        )
        return 'YES' in resp.text.strip().upper()
    except Exception:
        return False

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────
TOKEN_JAC_THRESHOLD = 0.50    
PLACEHOLDER_RE  = re.compile(
    r"^(uVar|iVar|lVar|pcVar|pvVar|bVar|dVar|"
    r"local_|param_|DAT_|FUN_|PTR_|WORD_|DWORD_|BYTE_|"
    r"extraout_|in_)\d"
)

# ─────────────────────────────────────────────────────────────────────────────
# String similarity helpers
# ─────────────────────────────────────────────────────────────────────────────

def _normalise(name: str) -> str:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return re.sub(r"[\s_\-]+", "", spaced.lower())

def _tokenise(name: str) -> set[str]:
    parts = re.split(r"[_\-]+", name)
    tokens: set[str] = set()
    for part in parts:
        sub = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", part)
        for t in sub.split("_"):
            t = t.lower().strip()
            if len(t) >= 2:
                tokens.add(t)
    return tokens

def _jaccard(a: str, b: str) -> float:
    ta, tb = _tokenise(a), _tokenise(b)
    if not ta or not tb: return 0.0
    return len(ta & tb) / len(ta | tb)

def _levenshtein(a: str, b: str) -> float:
    if a == b: return 1.0
    if not a or not b: return 0.0
    la, lb = len(a), len(b)
    prev = list(range(lb + 1))
    curr = [0] * (lb + 1)
    for i in range(1, la + 1):
        curr[0] = i
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        prev, curr = curr, prev
    dist = prev[lb]
    return 1.0 - dist / max(la, lb)

def _best_similarity(recovered: str, gt_set: set[str]) -> tuple[float, Optional[str]]:
    best_score, closest = 0.0, None
    for g in gt_set:
        lev  = _levenshtein(recovered, g)
        jac  = _jaccard(recovered, g)
        score = max(lev, jac)
        if score > best_score:
            best_score, closest = score, g
    return best_score, closest

def _match_level(recovered: str, gt_set: set[str]) -> Optional[str]:
    if recovered in gt_set:
        return "exact"
    norm_recovered = _normalise(recovered)
    if norm_recovered in {_normalise(g) for g in gt_set}:
        return "normalised"
    
    best_lev  = max((_levenshtein(recovered, g) for g in gt_set), default=0.0)
    best_jac  = max((_jaccard(recovered, g)      for g in gt_set), default=0.0)
    
    if max(best_lev, best_jac) >= FUZZY_MATCH_THRESHOLD:
        return "fuzzy"
        
    # FIXED: If lexical fuzzy matching fails, ask the LLM Judge 
    if USE_LLM_JUDGE:
        _, closest = _best_similarity(recovered, gt_set)
        if closest and _semantic_match(recovered, closest):
            return "fuzzy" # Treat LLM semantic match as fuzzy
            
    return None

def _match_function_level(recovered: str, gt_set: set[str]) -> Optional[str]:
    tier = _match_level(recovered, gt_set)
    if tier:
        return tier
    rl = recovered.lower()
    for g in gt_set:
        gl = g.lower()
        if rl in gl or gl in rl:
            return "partial"
    return None

# ─────────────────────────────────────────────────────────────────────────────
# Data classes for results
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class NameMatch:
    original_key:     str            
    recovered_name:   str            
    match_tier:       Optional[str]  
    closest_gt_name:  Optional[str]  
    similarity:       float          

@dataclass
class TierCounts:
    exact:       int = 0
    normalised:  int = 0
    fuzzy:       int = 0
    partial:     int = 0   
    no_match:    int = 0

    @property
    def any_match(self) -> int:
        return self.exact + self.normalised + self.fuzzy + self.partial

    def to_dict(self) -> dict:
        total = self.any_match + self.no_match
        def pct(n): return round(100 * n / total, 1) if total else 0.0
        return {
            "exact":          self.exact,
            "normalised":     self.normalised,
            "fuzzy":          self.fuzzy,
            "partial":        self.partial,
            "no_match":       self.no_match,
            "total_renamed":  total,
            "pct_exact":       pct(self.exact),
            "pct_normalised":  pct(self.normalised),
            "pct_fuzzy":       pct(self.fuzzy),
            "pct_partial":     pct(self.partial),
            "pct_no_match":    pct(self.no_match),
        }

@dataclass
class MetricSet:
    precision:  float
    recall:     float
    f1:         float
    coverage:   float    

    def to_dict(self) -> dict:
        return {
            "precision": round(self.precision, 4),
            "recall":    round(self.recall,    4),
            "f1":        round(self.f1,        4),
            "coverage":  round(self.coverage,  4),
        }

@dataclass
class EvalResults:
    gt_function_count:       int
    gt_variable_count:       int
    agent_function_renames:  int   
    agent_variable_renames:  int   

    function_matches:   list[NameMatch]
    function_tiers:     TierCounts
    function_metrics:   dict[str, MetricSet]   

    variable_matches:   list[NameMatch]
    variable_tiers:     TierCounts
    variable_metrics:   dict[str, MetricSet]

    per_function:       dict   

    overall_score:      float  

    def to_dict(self) -> dict:
        return {
            "summary": {
                "gt_functions":          self.gt_function_count,
                "gt_variables":          self.gt_variable_count,
                "agent_function_renames": self.agent_function_renames,
                "agent_variable_renames": self.agent_variable_renames,
                "overall_score":          round(self.overall_score, 4),
            },
            "function_recovery": {
                "tiers":   self.function_tiers.to_dict(),
                "metrics": {k: v.to_dict() for k, v in self.function_metrics.items()},
                "matches": [
                    {
                        "placeholder":     m.original_key,
                        "recovered":       m.recovered_name,
                        "tier":            m.match_tier,
                        "closest_gt":      m.closest_gt_name,
                        "similarity":      round(m.similarity, 3),
                    }
                    for m in self.function_matches
                ],
            },
            "variable_recovery": {
                "tiers":   self.variable_tiers.to_dict(),
                "metrics": {k: v.to_dict() for k, v in self.variable_metrics.items()},
                "matches": [
                    {
                        "placeholder":    m.original_key,
                        "recovered":      m.recovered_name,
                        "tier":           m.match_tier,
                        "closest_gt":     m.closest_gt_name,
                        "similarity":     round(m.similarity, 3),
                    }
                    for m in self.variable_matches
                ],
            },
            "per_function": self.per_function,
        }

# ─────────────────────────────────────────────────────────────────────────────
# Evaluation logic
# ─────────────────────────────────────────────────────────────────────────────

def _compute_metrics(
    true_positives_exact:  int,
    true_positives_any:    int,
    agent_renamed:         int,
    gt_total:              int,
    gt_touched:            int,
) -> dict[str, MetricSet]:
    def _ms(tp: int) -> MetricSet:
        precision = tp / agent_renamed if agent_renamed else 0.0
        recall    = tp / gt_total      if gt_total      else 0.0
        f1 = (2 * precision * recall / (precision + recall)
              if (precision + recall) else 0.0)
        coverage  = gt_touched / gt_total if gt_total else 0.0
        return MetricSet(precision, recall, f1, coverage)

    return {
        "exact": _ms(true_positives_exact),
        "any":   _ms(true_positives_any),
    }

def evaluate(gt: GroundTruth, agent_output: dict) -> EvalResults:
    symbol_table: dict[str, str] = agent_output.get("symbol_table", {})
    agent_funcs:  dict           = agent_output.get("functions",    {})

    gt_func_names = gt.all_function_names
    gt_var_names  = gt.all_variable_names

    func_renames: list[tuple[str, str]] = []   
    var_renames:  list[tuple[str, str]] = []

    for placeholder, recovered in symbol_table.items():
        if not recovered or recovered == placeholder:
            continue
        if placeholder.upper().startswith("FUN_"):
            func_renames.append((placeholder, recovered))
        else:
            var_renames.append((placeholder, recovered))

    # ── Function matches ──────────────────────────────────────────────────────
    function_matches: list[NameMatch] = []
    func_tiers = TierCounts()
    gt_funcs_touched: set[str] = set()

    for placeholder, recovered in func_renames:
        best_sim, closest = _best_similarity(recovered, gt_func_names)
        tier              = _match_function_level(recovered, gt_func_names)

        if tier == "exact":
            func_tiers.exact += 1
            gt_funcs_touched.add(recovered)
        elif tier == "normalised":
            func_tiers.normalised += 1
            gt_funcs_touched.add(closest or "")
        elif tier == "fuzzy":
            func_tiers.fuzzy += 1
            gt_funcs_touched.add(closest or "")
        elif tier == "partial":
            func_tiers.partial += 1
            gt_funcs_touched.add(closest or "")
        else:
            func_tiers.no_match += 1

        function_matches.append(NameMatch(
            original_key=placeholder,
            recovered_name=recovered,
            match_tier=tier,
            closest_gt_name=closest,
            similarity=round(best_sim, 3),
        ))

    function_metrics = _compute_metrics(
        true_positives_exact = func_tiers.exact,
        true_positives_any   = func_tiers.any_match,
        agent_renamed        = len(func_renames),
        gt_total             = len(gt_func_names),
        gt_touched           = len(gt_funcs_touched),
    )

    # ── Variable matches ──────────────────────────────────────────────────────
    variable_matches: list[NameMatch] = []
    var_tiers = TierCounts()
    gt_vars_touched: set[str] = set()

    for placeholder, recovered in var_renames:
        best_sim, closest = _best_similarity(recovered, gt_var_names)
        tier              = _match_level(recovered, gt_var_names)

        if tier == "exact":
            var_tiers.exact += 1
            gt_vars_touched.add(recovered)
        elif tier == "normalised":
            var_tiers.normalised += 1
            gt_vars_touched.add(closest or "")
        elif tier == "fuzzy":
            var_tiers.fuzzy += 1
            gt_vars_touched.add(closest or "")
        else:
            var_tiers.no_match += 1

        variable_matches.append(NameMatch(
            original_key=placeholder,
            recovered_name=recovered,
            match_tier=tier,
            closest_gt_name=closest,
            similarity=round(best_sim, 3),
        ))

    variable_metrics = _compute_metrics(
        true_positives_exact = var_tiers.exact,
        true_positives_any   = var_tiers.any_match,
        agent_renamed        = len(var_renames),
        gt_total             = len(gt_var_names),
        gt_touched           = len(gt_vars_touched),
    )

    # ── Per-function breakdown ────────────────────────────────────────────────
    per_function: dict = {}

    for func_key, func_data in agent_funcs.items():
        status        = func_data.get("status", "UNKNOWN")
        recovered_fn  = symbol_table.get(func_key, func_key)
        fn_tier       = _match_function_level(recovered_fn, gt_func_names)

        per_function[func_key] = {
            "status":              status,
            "recovered_func_name": recovered_fn,
            "func_name_tier":      fn_tier,
            "summary":             func_data.get("summary", ""),
        }

    # ── Overall score ─────────────────────────────────────────────────────────
    fn_f1  = function_metrics["any"].f1
    var_f1 = variable_metrics["any"].f1
    overall_score = 0.4 * fn_f1 + 0.6 * var_f1

    return EvalResults(
        gt_function_count       = len(gt_func_names),
        gt_variable_count       = len(gt_var_names),
        agent_function_renames  = len(func_renames),
        agent_variable_renames  = len(var_renames),
        function_matches        = function_matches,
        function_tiers          = func_tiers,
        function_metrics        = function_metrics,
        variable_matches        = variable_matches,
        variable_tiers          = var_tiers,
        variable_metrics        = variable_metrics,
        per_function            = per_function,
        overall_score           = overall_score,
    )