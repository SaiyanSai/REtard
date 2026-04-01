"""
report_generator.py  –  Turn EvalResults into human-readable outputs.

Generates:
  • eval_report.json  –  machine-readable full results
  • eval_report.html  –  rich HTML page with colour-coded tables and gauges
"""

import json
import re
from datetime import datetime
from pathlib import Path

from evaluator import EvalResults


# ─────────────────────────────────────────────────────────────────────────────
# JSON report
# ─────────────────────────────────────────────────────────────────────────────

def save_json_report(results: EvalResults, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results.to_dict(), f, indent=2)
    print(f"[report] JSON saved → {path}")
    return path


# ─────────────────────────────────────────────────────────────────────────────
# HTML report helpers
# ─────────────────────────────────────────────────────────────────────────────

_TIER_COLOUR = {
    "exact":      "#22c55e",   # green
    "normalised": "#84cc16",   # lime
    "fuzzy":      "#eab308",   # yellow
    "partial":    "#f97316",   # orange
    None:         "#ef4444",   # red  (no match)
}

_TIER_LABEL = {
    "exact":      "✔ Exact",
    "normalised": "≈ Normalised",
    "fuzzy":      "~ Fuzzy",
    "partial":    "⊃ Partial",
    None:         "✘ No match",
}


def _score_colour(score: float) -> str:
    if score >= 0.75:  return "#22c55e"
    if score >= 0.50:  return "#eab308"
    if score >= 0.25:  return "#f97316"
    return "#ef4444"


def _gauge_svg(value: float, label: str, size: int = 110) -> str:
    """Minimal circular gauge SVG."""
    pct  = max(0.0, min(1.0, value))
    circ = 2 * 3.14159 * 40
    dash = circ * pct
    colour = _score_colour(pct)
    text = f"{pct*100:.1f}%"
    return f"""
<svg width="{size}" height="{size}" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
  <circle cx="50" cy="50" r="40" fill="none" stroke="#e5e7eb" stroke-width="10"/>
  <circle cx="50" cy="50" r="40" fill="none" stroke="{colour}" stroke-width="10"
    stroke-dasharray="{dash:.2f} {circ:.2f}"
    stroke-dashoffset="{circ/4:.2f}"
    transform="rotate(-90 50 50)"/>
  <text x="50" y="48" text-anchor="middle" dominant-baseline="middle"
        font-size="14" font-weight="bold" fill="{colour}">{text}</text>
  <text x="50" y="64" text-anchor="middle" dominant-baseline="middle"
        font-size="8" fill="#6b7280">{label}</text>
</svg>"""


def _match_table(matches: list, title: str) -> str:
    rows = []
    for m in sorted(matches, key=lambda x: (x.match_tier or "z", x.original_key)):
        colour = _TIER_COLOUR[m.match_tier]
        label  = _TIER_LABEL[m.match_tier]
        closest = m.closest_gt_name or "—"
        rows.append(f"""
      <tr>
        <td><code>{m.original_key}</code></td>
        <td><strong>{m.recovered_name}</strong></td>
        <td style="color:{colour};font-weight:bold">{label}</td>
        <td>{closest}</td>
        <td>{m.similarity:.2%}</td>
      </tr>""")

    rows_html = "".join(rows)
    return f"""
  <h3>{title}</h3>
  <div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>Placeholder (Ghidra)</th>
        <th>Recovered Name</th>
        <th>Match Tier</th>
        <th>Closest GT Name</th>
        <th>Similarity</th>
      </tr>
    </thead>
    <tbody>{rows_html}
    </tbody>
  </table>
  </div>"""


def _tier_bar(tiers: dict, total: int) -> str:
    """Stacked progress bar for tier breakdown."""
    colours = {
        "exact": "#22c55e", "normalised": "#84cc16",
        "fuzzy": "#eab308", "partial": "#f97316", "no_match": "#ef4444",
    }
    parts = []
    for key, colour in colours.items():
        count = tiers.get(key, 0)
        if count == 0 or total == 0:
            continue
        pct = count / total * 100
        parts.append(
            f'<div style="width:{pct:.1f}%;background:{colour};height:100%;'
            f'display:inline-block;vertical-align:top;'
            f'title="{key}: {count}"></div>'
        )
    legend = " ".join(
        f'<span style="color:{c}">■</span> {k}'
        for k, c in colours.items()
        if tiers.get(k, 0) > 0
    )
    return f"""
<div style="height:20px;background:#e5e7eb;border-radius:4px;overflow:hidden">
  {''.join(parts)}
</div>
<small style="color:#6b7280">{legend}</small>"""


def _per_func_table(per_function: dict) -> str:
    rows = []
    for key, data in sorted(per_function.items()):
        tier   = data.get("func_name_tier")
        colour = _TIER_COLOUR[tier]
        label  = _TIER_LABEL[tier]
        status = data.get("status", "?")
        recovered = data.get("recovered_func_name", key)
        summary = (data.get("summary") or "—")[:120]
        rows.append(f"""
      <tr>
        <td><code>{key}</code></td>
        <td><strong>{recovered}</strong></td>
        <td style="color:{colour};font-weight:bold">{label}</td>
        <td><span class="badge badge-{status.lower()}">{status}</span></td>
        <td style="font-size:0.8em;color:#6b7280">{summary}</td>
      </tr>""")

    rows_html = "".join(rows)
    return f"""
  <h3>Per-function Breakdown</h3>
  <div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>Placeholder</th><th>Recovered Name</th>
        <th>Name Match Tier</th><th>Agent Status</th><th>Summary</th>
      </tr>
    </thead>
    <tbody>{rows_html}</tbody>
  </table>
  </div>"""


# ─────────────────────────────────────────────────────────────────────────────
# HTML report
# ─────────────────────────────────────────────────────────────────────────────

def save_html_report(
    results: EvalResults,
    path: str | Path,
    source_file: str = "",
) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    d = results.to_dict()
    summary = d["summary"]
    fn_r    = d["function_recovery"]
    vr_r    = d["variable_recovery"]

    fn_any_metrics  = fn_r["metrics"]["any"]
    var_any_metrics = vr_r["metrics"]["any"]
    overall         = summary["overall_score"]

    fn_tiers  = fn_r["tiers"]
    var_tiers = vr_r["tiers"]

    gauges_html = "".join([
        _gauge_svg(overall,                       "Overall Score"),
        _gauge_svg(fn_any_metrics["f1"],          "Func F1"),
        _gauge_svg(fn_any_metrics["precision"],   "Func Precision"),
        _gauge_svg(fn_any_metrics["recall"],      "Func Recall"),
        _gauge_svg(var_any_metrics["f1"],         "Var F1"),
        _gauge_svg(var_any_metrics["precision"],  "Var Precision"),
        _gauge_svg(var_any_metrics["recall"],     "Var Recall"),
    ])

    fn_match_table  = _match_table(results.function_matches,  "Function Name Matches")
    var_match_table = _match_table(results.variable_matches,  "Variable Name Matches")
    func_breakdown  = _per_func_table(results.per_function)

    fn_bar  = _tier_bar(fn_tiers,  fn_tiers.get("total_renamed", 1) if isinstance(fn_tiers, dict) else fn_tiers.any_match + fn_tiers.no_match)
    var_bar = _tier_bar(var_tiers, var_tiers.get("total_renamed", 1) if isinstance(var_tiers, dict) else var_tiers.any_match + var_tiers.no_match)

    # Compute tier dicts for bars
    fn_td  = fn_tiers  if isinstance(fn_tiers,  dict) else fn_tiers.to_dict()
    var_td = var_tiers if isinstance(var_tiers, dict) else var_tiers.to_dict()
    fn_bar  = _tier_bar(fn_td,  fn_td.get("total_renamed", 1))
    var_bar = _tier_bar(var_td, var_td.get("total_renamed", 1))

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>REtard Eval Report – {source_file or 'unknown'}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #f9fafb;
          color: #111827; line-height: 1.6; }}
  header {{ background: #111827; color: #f9fafb; padding: 1.5rem 2rem; }}
  header h1 {{ font-size: 1.6rem; }}
  header p  {{ color: #9ca3af; font-size: 0.9rem; }}
  main {{ max-width: 1200px; margin: 2rem auto; padding: 0 1.5rem; }}
  .section {{ background: #fff; border-radius: 10px; padding: 1.5rem;
              margin-bottom: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,.1); }}
  h2 {{ font-size: 1.2rem; margin-bottom: 1rem; color: #1f2937;
        border-bottom: 2px solid #e5e7eb; padding-bottom: .5rem; }}
  h3 {{ font-size: 1rem; margin: 1rem 0 .5rem; color: #374151; }}
  .gauges {{ display: flex; gap: .75rem; flex-wrap: wrap; align-items: center; }}
  .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fill,minmax(180px,1fr));
                gap: 1rem; margin-bottom: 1rem; }}
  .stat-card {{ background:#f3f4f6; border-radius:8px; padding:.75rem 1rem; }}
  .stat-card .val {{ font-size:1.5rem; font-weight:700; }}
  .stat-card .lbl {{ font-size:.8rem; color:#6b7280; }}
  .table-wrap {{ overflow-x: auto; }}
  table {{ width:100%; border-collapse:collapse; font-size:.85rem; }}
  th {{ background:#f3f4f6; padding:.5rem .75rem; text-align:left;
        font-size:.78rem; text-transform:uppercase; color:#6b7280;
        border-bottom:2px solid #e5e7eb; }}
  td {{ padding:.45rem .75rem; border-bottom:1px solid #f3f4f6; vertical-align:top; }}
  tr:hover td {{ background:#f9fafb; }}
  code {{ background:#f3f4f6; padding:.1rem .3rem; border-radius:3px;
          font-family:monospace; font-size:.82em; }}
  .badge {{ display:inline-block; padding:.1rem .5rem; border-radius:999px;
            font-size:.7rem; font-weight:600; text-transform:uppercase; }}
  .badge-analyzed   {{ background:#dcfce7; color:#166534; }}
  .badge-pending    {{ background:#fef9c3; color:#854d0e; }}
  .badge-partial    {{ background:#fff7ed; color:#9a3412; }}
  .badge-obfuscated {{ background:#fce7f3; color:#9d174d; }}
  .badge-partial_end{{ background:#fee2e2; color:#991b1b; }}
  footer {{ text-align:center; color:#9ca3af; font-size:.8rem; padding:2rem; }}
</style>
</head>
<body>
<header>
  <h1>🔍 REtard Evaluation Report</h1>
  <p>Source: <strong>{source_file or '—'}</strong> &nbsp;|&nbsp; Generated: {ts}</p>
</header>
<main>

<!-- Summary gauges -->
<div class="section">
  <h2>Overall Performance</h2>
  <div class="gauges">{gauges_html}</div>
</div>

<!-- Inventory stats -->
<div class="section">
  <h2>Inventory</h2>
  <div class="stat-grid">
    <div class="stat-card">
      <div class="val">{summary['gt_functions']}</div>
      <div class="lbl">Ground-truth functions</div>
    </div>
    <div class="stat-card">
      <div class="val">{summary['gt_variables']}</div>
      <div class="lbl">Ground-truth variables</div>
    </div>
    <div class="stat-card">
      <div class="val">{summary['agent_function_renames']}</div>
      <div class="lbl">Functions renamed by agent</div>
    </div>
    <div class="stat-card">
      <div class="val">{summary['agent_variable_renames']}</div>
      <div class="lbl">Variables renamed by agent</div>
    </div>
    <div class="stat-card">
      <div class="val" style="color:{_score_colour(overall)}">{overall:.1%}</div>
      <div class="lbl">Overall Score (weighted F1)</div>
    </div>
  </div>
</div>

<!-- Function recovery -->
<div class="section">
  <h2>Function Name Recovery</h2>
  <div class="stat-grid">
    <div class="stat-card"><div class="val">{fn_any_metrics['precision']:.1%}</div><div class="lbl">Precision (any tier)</div></div>
    <div class="stat-card"><div class="val">{fn_any_metrics['recall']:.1%}</div><div class="lbl">Recall (any tier)</div></div>
    <div class="stat-card"><div class="val">{fn_any_metrics['f1']:.1%}</div><div class="lbl">F1 (any tier)</div></div>
    <div class="stat-card"><div class="val">{fn_any_metrics['coverage']:.1%}</div><div class="lbl">Coverage</div></div>
    <div class="stat-card"><div class="val">{fn_td['pct_exact']}%</div><div class="lbl">Exact matches</div></div>
  </div>
  <h3>Match distribution</h3>
  {fn_bar}
  {fn_match_table}
</div>

<!-- Variable recovery -->
<div class="section">
  <h2>Variable Name Recovery</h2>
  <div class="stat-grid">
    <div class="stat-card"><div class="val">{var_any_metrics['precision']:.1%}</div><div class="lbl">Precision (any tier)</div></div>
    <div class="stat-card"><div class="val">{var_any_metrics['recall']:.1%}</div><div class="lbl">Recall (any tier)</div></div>
    <div class="stat-card"><div class="val">{var_any_metrics['f1']:.1%}</div><div class="lbl">F1 (any tier)</div></div>
    <div class="stat-card"><div class="val">{var_any_metrics['coverage']:.1%}</div><div class="lbl">Coverage</div></div>
    <div class="stat-card"><div class="val">{var_td['pct_exact']}%</div><div class="lbl">Exact matches</div></div>
  </div>
  <h3>Match distribution</h3>
  {var_bar}
  {var_match_table}
</div>

<!-- Per-function -->
<div class="section">
  <h2>Per-function Breakdown</h2>
  {func_breakdown}
</div>

</main>
<footer>REtard Automated Evaluation Framework</footer>
</body>
</html>"""

    path.write_text(html, encoding="utf-8")
    print(f"[report] HTML saved → {path}")
    return path
