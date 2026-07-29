"""Self-contained, print-ready HTML report renderer for coder56 engagements.

Produces a single HTML document (inline CSS, no external assets/JS beyond the
print button) rendered server-side from an engagement + its runs + findings.
The frontend opens it in a new tab; the user uses the browser's "Print / Save
as PDF" (the page ships @media print CSS for clean page breaks, running footer
page numbers, and a hidden toolbar).

No template engine / no binary deps — just a Python string builder + a tiny
markdown-subset renderer for operator/LLM-authored finding fields.

Severity colors are HARDCODED to a light palette so the report prints correctly
on white regardless of the console's dark/light theme.
"""
from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Any, Dict, List

# Light severity palette (works on white paper; never inherits the app theme).
SEV_COLORS = {
    "critical": ("#9f1239", "#fee2e2"),
    "high":     ("#9a3412", "#ffedd5"),
    "medium":   ("#854d0e", "#fef9c3"),
    "low":      ("#166534", "#dcfce7"),
    "info":     ("#334155", "#e2e8f0"),
}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]


# =============================================================================
# Tiny markdown-subset renderer (headings, bold, inline code, code fences, lists)
# =============================================================================

def _escape(text: str) -> str:
    return html.escape(text or "")


def _inline(text: str) -> str:
    """Inline formatting: bold (**..** / __..__) and inline code (`..`)."""
    out = []
    i = 0
    n = len(text)
    while i < n:
        if text.startswith("**", i) or text.startswith("__", i):
            marker = text[i:i + 2]
            end = text.find(marker, i + 2)
            if end != -1:
                out.append(f"<strong>{_escape(text[i + 2:end])}</strong>")
                i = end + 2
                continue
        if text[i] == "`":
            end = text.find("`", i + 1)
            if end != -1:
                out.append(f"<code>{_escape(text[i + 1:end])}</code>")
                i = end + 1
                continue
        out.append(_escape(text[i]))
        i += 1
    return "".join(out)


def _md(text: str) -> str:
    """Render a markdown subset to HTML. Safe (all text is escaped)."""
    if not text:
        return ""
    lines = text.replace("\r\n", "\n").split("\n")
    out: List[str] = []
    in_fence = False
    fence_buf: List[str] = []
    para: List[str] = []
    list_items: List[str] = []

    def flush_para() -> None:
        if para:
            out.append("<p>" + " ".join(_inline(l) for l in para) + "</p>")
            para.clear()

    def flush_list() -> None:
        if list_items:
            out.append("<ul>" + "".join(f"<li>{_inline(it)}</li>" for it in list_items) + "</ul>")
            list_items.clear()

    for raw in lines:
        line = raw.rstrip()
        # Fenced code blocks
        if line.lstrip().startswith("```"):
            if in_fence:
                out.append('<pre><code>' + _escape("\n".join(fence_buf)) + "</code></pre>")
                fence_buf.clear()
                in_fence = False
            else:
                flush_para(); flush_list()
                in_fence = True
            continue
        if in_fence:
            fence_buf.append(raw)
            continue
        if not line.strip():
            flush_para(); flush_list()
            continue
        # Headings
        if line.startswith("### "):
            flush_para(); flush_list()
            out.append(f"<h4>{_inline(line[4:].strip())}</h4>")
            continue
        if line.startswith("## "):
            flush_para(); flush_list()
            out.append(f"<h3>{_inline(line[3:].strip())}</h3>")
            continue
        if line.startswith("# "):
            flush_para(); flush_list()
            out.append(f"<h3>{_inline(line[2:].strip())}</h3>")
            continue
        # Bullet list items
        stripped = line.lstrip()
        if stripped.startswith(("- ", "* ", "• ")):
            flush_para()
            list_items.append(stripped[2:].strip())
            continue
        # Default: paragraph text
        flush_list()
        para.append(line.strip())
    flush_para(); flush_list()
    if in_fence and fence_buf:
        out.append('<pre><code>' + _escape("\n".join(fence_buf)) + "</code></pre>")
    return "\n".join(out)


# =============================================================================
# Helpers
# =============================================================================

def _mitre_index(mitre: Dict[str, Any]) -> Dict[str, str]:
    """Flat {id -> 'Name'} for tactics + techniques, for report name resolution."""
    idx: Dict[str, str] = {}
    for tac in (mitre.get("tactics") or []):
        idx[tac.get("id", "")] = tac.get("name", "")
        for tech in (tac.get("techniques") or []):
            idx[tech.get("id", "")] = tech.get("name", "")
    return idx


def _sev_badge(sev: str) -> str:
    fg, bg = SEV_COLORS.get((sev or "").lower(), SEV_COLORS["info"])
    return (f'<span class="sev" style="background:{bg};color:{fg}">'
            f'{_escape((sev or "info").upper())}</span>')


def _status_dot(status: str) -> str:
    color = {"open": "#dc2626", "remediating": "#d97706",
             "fixed": "#16a34a", "accepted": "#64748b"}.get((status or "open"), "#64748b")
    return f'<span class="dot" style="background:{color}"></span>{_escape(status or "open")}'


def _verified_badge(f: Dict[str, Any]) -> str:
    """Verifier-provenance badge. Green check when the coder56_verifier
    CONFIRMED the claim; a muted 'refuted' tag when it ruled the claim out;
    nothing when the finding was never verifier-checked."""
    vv = (f.get("verifier_verdict") or "").strip()
    if f.get("verified"):
        title = f' title="{_escape(vv)}"' if vv else ""
        return f'<span class="vbadge verified"{title}>&#10003; Verifier-confirmed</span>'
    if vv:
        return f'<span class="vbadge refuted" title="{_escape(vv)}">Refuted by verifier</span>'
    return ""


def _findings_tally(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    tally = {s: 0 for s in SEV_ORDER}
    for f in findings:
        s = (f.get("severity") or "info").lower()
        tally[s] = tally.get(s, 0) + 1
    return tally


def _mean_cvss(findings: List[Dict[str, Any]]) -> str:
    scores = [float(f["cvss"]) for f in findings
              if f.get("cvss") is not None and _is_num(f.get("cvss"))]
    if not scores:
        return "—"
    return f"{sum(scores) / len(scores):.1f}"


def _is_num(v: Any) -> bool:
    try:
        float(v)
        return True
    except (TypeError, ValueError):
        return False


# =============================================================================
# Report
# =============================================================================

_CSS = """
*{box-sizing:border-box}
body{font-family:-apple-system,'Segoe UI',Inter,Roboto,Helvetica,Arial,sans-serif;
  color:#1e293b;margin:0;background:#eef2f7;line-height:1.5;font-size:11pt}
.report{max-width:820px;margin:0 auto;background:#fff;padding:48px 56px;min-height:100vh}
.toolbar{position:sticky;top:0;z-index:10;background:#0f172a;color:#fff;display:flex;
  gap:10px;align-items:center;padding:10px 16px;font-size:13px;font-family:inherit}
.toolbar .tb-title{font-weight:600;letter-spacing:.02em}
.toolbar button{background:#4f46e5;color:#fff;border:0;border-radius:6px;padding:7px 14px;
  font-weight:600;font-size:13px;cursor:pointer;font-family:inherit}
.toolbar button.ghost{background:transparent;border:1px solid #475569;color:#cbd5e1}
.toolbar .spacer{flex:1}
.cover{min-height:80vh;display:flex;flex-direction:column;justify-content:center;
  page-break-after:always;border-bottom:3px solid #4f46e5;padding-bottom:32px}
.cover .kicker{color:#4f46e5;font-weight:700;letter-spacing:.18em;text-transform:uppercase;font-size:11pt}
.cover h1{font-size:34pt;margin:10px 0 6px;color:#0f172a;line-height:1.1}
.cover .sub{color:#475569;font-size:14pt;margin-bottom:28px}
.cover .meta{display:grid;grid-template-columns:120px 1fr;gap:8px 18px;font-size:11pt}
.cover .meta dt{color:#64748b;font-weight:600}
.cover .meta dd{margin:0;color:#0f172a}
.tally{display:flex;gap:10px;flex-wrap:wrap;margin-top:24px}
.tally .chip{padding:8px 14px;border-radius:8px;font-weight:700;font-size:11pt}
h2.sec{font-size:17pt;color:#0f172a;border-bottom:2px solid #e2e8f0;padding-bottom:6px;
  margin:34px 0 12px;page-break-after:avoid}
h3{font-size:13pt;color:#1e293b;margin:18px 0 6px;page-break-after:avoid}
p{margin:6px 0}
.finding{border:1px solid #e2e8f0;border-left:5px solid #cbd5e1;border-radius:8px;
  padding:14px 18px;margin:14px 0;page-break-inside:avoid}
.finding .head{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:6px}
.finding .head .t{font-size:13pt;font-weight:700;color:#0f172b;flex:1}
.finding .asset{font-size:10pt;color:#64748b}
.finding dl.meta{display:grid;grid-template-columns:96px 1fr;gap:4px 14px;font-size:10.5pt;margin:8px 0}
.finding dl.meta dt{color:#64748b;font-weight:600}
.finding dl.meta dd{margin:0}
.finding .evidence{background:#0f172a;color:#e2e8f0;border-radius:6px;padding:10px 12px;
  font-family:'JetBrains Mono',ui-monospace,Menlo,Consolas,monospace;font-size:9.5pt;
  white-space:pre-wrap;word-break:break-word;margin:8px 0}
.finding pre{background:#0f172a;color:#e2e8f0;border-radius:6px;padding:10px 12px;font-size:9.5pt;
  white-space:pre-wrap;word-break:break-word;font-family:'JetBrains Mono',ui-monospace,Menlo,Consolas,monospace}
table{width:100%;border-collapse:collapse;font-size:9.8pt;margin:8px 0}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #e2e8f0;vertical-align:top}
th{color:#64748b;font-weight:700;text-transform:uppercase;font-size:8.5pt;letter-spacing:.04em}
td.cmd{font-family:'JetBrains Mono',ui-monospace,Menlo,Consolas,monospace;font-size:9pt;
  word-break:break-all;max-width:380px}
.sev{display:inline-block;padding:2px 8px;border-radius:5px;font-size:8.5pt;font-weight:700}
.vbadge{display:inline-block;padding:2px 8px;border-radius:5px;font-size:8.5pt;font-weight:700;margin-left:2px}
.vbadge.verified{background:#dcfce7;color:#166534}
.vbadge.refuted{background:#fee2e2;color:#9f1239}
.owasp{display:inline-block;padding:2px 8px;border-radius:5px;font-size:8.5pt;font-weight:700;
  margin-left:2px;background:#eef2ff;color:#3730a3}
.vverdict{font-size:9.5pt;color:#475569;margin:6px 0}
.cmds{margin:8px 0}
.cmds-label{font-size:8.5pt;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:.04em;margin-bottom:4px}
.finding .cmds pre{margin:4px 0}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:5px;vertical-align:middle}
.muted{color:#64748b}
.run{page-break-inside:avoid;margin:12px 0;padding:10px 14px;border:1px solid #e2e8f0;border-radius:8px}
.note{background:#f1f5f9;border-radius:8px;padding:10px 14px;color:#475569;font-size:10pt;margin:10px 0}
@media print{
  body{background:#fff;font-size:10.5pt}
  .report{max-width:none;margin:0;padding:0}
  .toolbar{display:none}
  .cover{min-height:auto}
  @page{size:A4;margin:18mm 16mm}
  @page :first{margin:0}
  .cover{padding:40mm 16mm 12mm}
  h2.sec{page-break-before:always}
  h2.sec:first-of-type{page-break-before:auto}
  .finding,.run,tr,thead{page-break-inside:avoid}
}
"""


def _cover(eng: Dict[str, Any], tally: Dict[str, int], generated_at: str) -> str:
    status = (eng.get("status") or "planning").replace("_", " ")
    return f"""
<section class="cover">
  <div class="kicker">Authorized Cyber-Range · Penetration Test Report</div>
  <h1>{_escape(eng.get('name') or 'Untitled Engagement')}</h1>
  <div class="sub">{_escape(eng.get('client') or '—')}</div>
  <dl class="meta">
    <dt>Objective</dt><dd>{_escape(eng.get('objective') or '—')}</dd>
    <dt>Target scope</dt><dd class="mono">{_escape(eng.get('target_scope') or '—')}</dd>
    <dt>Status</dt><dd>{_escape(status)}</dd>
    <dt>Prepared</dt><dd>{_escape(generated_at)}</dd>
    <dt>Classification</dt><dd>CONFIDENTIAL — Authorized Security Testing</dd>
  </dl>
  <div class="tally">
    {''.join(f'<span class="chip" style="background:{SEV_COLORS[s][1]};color:{SEV_COLORS[s][0]}">{tally[s]} {s.upper()}</span>' for s in SEV_ORDER if tally.get(s))}
    {''.join(f'<span class="chip" style="background:#e2e8f0;color:#334155">{sum(tally.values())} TOTAL</span>' if sum(tally.values()) else '')}
  </div>
</section>"""


def _exec_summary(eng: Dict[str, Any], findings: List[Dict[str, Any]], tally: Dict[str, int], n_runs: int) -> str:
    total = sum(tally.values())
    crit = tally.get("critical", 0) + tally.get("high", 0)
    overall = ("Several high-impact issues were identified that should be prioritized for remediation."
               if crit else ("A measured set of findings was identified across the engagement."
               if total else "No findings were recorded for this engagement."))
    parts = [
        f"<p>{_escape(overall)}</p>",
        f"<p><b>Engagement:</b> {_escape(eng.get('name') or '')}. "
        f"<b>Objective:</b> {_escape(eng.get('objective') or '—')}.</p>",
        f"<p>This report covers <b>{n_runs}</b> execution run(s) and documents <b>{total}</b> finding(s) "
        f"(mean CVSS {_mean_cvss(findings)}): "
        + ", ".join(f"{tally[s]} {s}" for s in SEV_ORDER if tally.get(s)) + ".</p>",
    ]
    return f'<section><h2 class="sec">1. Executive Summary</h2>{"".join(parts)}</section>'


def _scope(eng: Dict[str, Any]) -> str:
    return f"""
<section><h2 class="sec">3. Scope &amp; Rules of Engagement</h2>
  <h3>Authorized scope</h3><p class="mono">{_escape(eng.get('target_scope') or '—') or '—'}</p>
  <h3>Rules of engagement</h3><p>{_md(eng.get('roe')) or '<span class="muted">—</span>'}</p>
</section>"""


def _methodology(runs: List[Dict[str, Any]], midx: Dict[str, str]) -> str:
    if not runs:
        return '<section><h2 class="sec">3. Methodology</h2><p class="muted">No runs recorded.</p></section>'
    blocks = []
    for i, run in enumerate(runs, 1):
        rid = run.get("run_id", "")
        crit = run.get("criticality", "—")
        rows = []
        for rt in run.get("phase_runtime") or []:
            tac = rt.get("tactic_id") or ""
            tac_name = f"{tac} · {midx.get(tac, '')}" if tac else "—"
            techs = rt.get("technique_ids") or []
            tech_str = ", ".join(f"{t} ({midx.get(t, '')})" if midx.get(t) else t for t in techs) or "—"
            status = (rt.get("status") or "").replace("_", " ")
            rows.append(
                f"<tr><td>{int(rt.get('index', 0)) + 1}</td><td>{_escape(tac_name)}</td>"
                f"<td>{_escape(tech_str)}</td><td>{_escape(status)}</td></tr>")
        crit_label = (f"<b>{_escape(crit)}</b>" if crit != "—" else "—")
        rows_html = "".join(rows) if rows else '<tr><td colspan="4"><span class="muted">Single-shot run (no phased chain).</span></td></tr>'
        blocks.append(f"""
<div class="run">
  <h3>Run {i} <span class="muted">· {_escape(rid)}</span></h3>
  <p><b>Criticality:</b> {crit_label}</p>
  <table><thead><tr><th>#</th><th>Tactic</th><th>Techniques</th><th>Status</th></tr></thead>
    <tbody>{rows_html}</tbody></table>
</div>""")
    return f'<section><h2 class="sec">4. Methodology (MITRE ATT&CK)</h2>{"".join(blocks)}</section>'


def _owasp_coverage(engagement: Dict[str, Any], findings: List[Dict[str, Any]],
                    number: str = "2") -> str:
    """OWASP Top-10 coverage matrix (only when the engagement carries a `plan`):
    one row per drafted category — status + how many findings (verified/total)
    came out of it. Gives the reader the 'what was tested vs. what was found'
    picture the per-category run model is built around. `number` is the section
    label (the deterministic report places this at 2, the client report at 4)."""
    plan = engagement.get("plan") or []
    if not plan:
        return ""
    counts: Dict[str, Dict[str, int]] = {}
    for f in findings:
        oid = f.get("owasp_id")
        if not oid:
            continue
        c = counts.setdefault(oid, {"f": 0, "c": 0})
        c["f"] += 1
        if f.get("verified"):
            c["c"] += 1
    rows = []
    for p in plan:
        oid = p.get("owasp_id", "")
        c = counts.get(oid, {"f": 0, "c": 0})
        status = (p.get("status") or "planned")
        assess = p.get("assessable", "black-box")
        if status == "planned" and assess == "white-box-only":
            disp, dot = "Not assessed (white-box-only)", "#94a3b8"
        elif status == "done":
            disp, dot = "Assessed", "#16a34a"
        elif status == "running":
            disp, dot = "In progress", "#d97706"
        elif status == "skipped":
            disp, dot = "Skipped", "#94a3b8"
        else:
            disp, dot = "Planned", "#94a3b8"
        fc = c["f"]
        fc_str = f'{c["c"]} confirmed / {fc}' if fc else "—"
        rows.append(
            f"<tr><td><b>{_escape(oid)}</b></td><td>{_escape(p.get('title', ''))}</td>"
            f"<td><span class='dot' style='background:{dot}'></span>{_escape(disp)}</td>"
            f"<td>{_escape(fc_str)}</td></tr>")
    assessed = sum(1 for p in plan if (p.get("status") in ("done", "running")))
    confirmed_total = sum(c["c"] for c in counts.values())
    return f"""
<section><h2 class="sec">{number}. OWASP Top-10 Coverage</h2>
  <p>This engagement runs one execution per OWASP Top-10 category. <b>{assessed}/{len(plan)}</b>
  categories assessed, yielding <b>{confirmed_total}</b> verifier-confirmed finding(s).</p>
  <table><thead><tr><th>ID</th><th>Category</th><th>Status</th><th>Findings</th></tr></thead>
    <tbody>{''.join(rows)}</tbody></table>
</section>"""


def _findings(findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return ('<section><h2 class="sec">5. Findings</h2>'
                '<div class="note">No findings documented. Draft findings from run evidence or add them manually in the engagement Findings tab.</div></section>')
    cards = []
    for n, f in enumerate(findings, 1):
        sev = (f.get("severity") or "info").lower()
        cvss = f.get("cvss")
        cvss = f"{float(cvss):.1f}" if _is_num(cvss) else "—"
        ev_html = (f'<div class="evidence">{_escape(f.get("evidence", "").strip())}</div>'
                   if (f.get("evidence") or "").strip() else "")
        vv = (f.get("verifier_verdict") or "").strip()
        vv_html = (f'<div class="vverdict"><b>Verifier:</b> {_escape(vv)}</div>' if vv else "")
        cmds = [str(c) for c in (f.get("commands") or []) if str(c).strip()]
        cmds_html = ""
        if cmds:
            cmds_html = ('<div class="cmds"><div class="cmds-label">Proof commands (verifier repro)</div>'
                         + "".join(f'<pre><code>{_escape(c)}</code></pre>' for c in cmds)
                         + '</div>')
        oid_html = (f'<span class="owasp">OWASP {_escape(f.get("owasp_id"))}</span>'
                    if f.get("owasp_id") else "")
        cards.append(f"""
<div class="finding" style="border-left-color:{SEV_COLORS.get(sev, SEV_COLORS['info'])[0]}">
  <div class="head">
    <span class="t">[{n}] {_escape(f.get('title') or 'Untitled')}</span>
    {_sev_badge(sev)} <span class="muted">CVSS {cvss}</span> {_verified_badge(f)}{oid_html}
  </div>
  <div class="asset"><b>Affected asset:</b> {_escape(f.get('affected_asset') or '—')}</div>
  <dl class="meta">
    <dt>Description</dt><dd>{_md(f.get('description')) or '<span class="muted">—</span>'}</dd>
    <dt>Impact</dt><dd>{_md(f.get('impact')) or '<span class="muted">—</span>'}</dd>
    <dt>Recommendation</dt><dd>{_md(f.get('recommendation')) or '<span class="muted">—</span>'}</dd>
    <dt>Status</dt><dd>{_status_dot(f.get('status') or 'open')}</dd>
  </dl>
  {vv_html}{cmds_html}{ev_html}
</div>""")
    return f'<section><h2 class="sec">5. Findings</h2>{"".join(cards)}</section>'


def _appendix(runs: List[Dict[str, Any]], verdicts_by_run: Dict[str, List[Dict[str, Any]]]) -> str:
    if not runs:
        return ""
    blocks = []
    for i, run in enumerate(runs, 1):
        rid = run.get("run_id", "")
        inner: List[str] = []
        # Phase summaries (captured agent output) — present even with no verdicts.
        summaries = [(int(rt.get("index", 0)), (rt.get("result") or "").strip())
                     for rt in (run.get("phase_runtime") or []) if (rt.get("result") or "").strip()]
        if summaries:
            inner.append("<h4>Phase summaries</h4>")
            for idx, res in sorted(summaries):
                inner.append(f'<div class="evidence">[Phase {idx + 1}]\n{_escape(res[:1200])}</div>')
        # Command log (guardrail verdicts).
        vs = verdicts_by_run.get(rid, [])
        if vs:
            rows = []
            for v in vs:
                tag = "executed" if v.get("executed") else (v.get("decision") or "—")
                color = "#16a34a" if v.get("executed") else "#dc2626"
                rows.append(
                    f"<tr><td>{_escape(str(v.get('ts', ''))[11:19])}</td>"
                    f"<td><span class='dot' style='background:{color}'></span>{_escape(tag)} ({_escape(str(v.get('exit_code', '')))})</td>"
                    f"<td class='cmd'>{_escape(str(v.get('command', '')))[:240]}</td></tr>")
            inner.append(f"<h4>Command log ({len(vs)})</h4>"
                         f"<table><thead><tr><th>Time</th><th>Decision</th><th>Command</th></tr></thead>"
                         f"<tbody>{''.join(rows)}</tbody></table>")
        if not inner:
            continue  # nothing to show for this run
        blocks.append(f'<div class="run"><h3>Run {i} · {_escape(rid)}</h3>{"".join(inner)}</div>')
    if not blocks:
        return ""
    return f'<section><h2 class="sec">6. Evidence Appendix</h2>{"".join(blocks)}</section>'


def render_report(engagement: Dict[str, Any],
                  runs: List[Dict[str, Any]],
                  findings: List[Dict[str, Any]],
                  mitre: Dict[str, Any],
                  verdicts_by_run: Dict[str, List[Dict[str, Any]]]) -> str:
    """Build the full self-contained HTML report string."""
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    tally = _findings_tally(findings)
    midx = _mitre_index(mitre)
    # findings already severity-sorted by the backend; sort defensively again.
    order = {s: i for i, s in enumerate(SEV_ORDER)}
    findings = sorted(findings, key=lambda f: order.get((f.get("severity") or "info").lower(), 99))

    body = (
        _cover(engagement, tally, generated_at)
        + _exec_summary(engagement, findings, tally, len(runs))
        + _owasp_coverage(engagement, findings)
        + _scope(engagement)
        + _methodology(runs, midx)
        + _findings(findings)
        + _appendix(runs, verdicts_by_run)
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_escape(engagement.get('name') or 'Engagement')} — Pentest Report</title>
<style>{_CSS}</style></head>
<body>
<div class="toolbar no-print">
  <span class="tb-title">◆ Pentest Report · {_escape(engagement.get('name') or '')}</span>
  <span class="spacer"></span>
  <button onclick="window.print()">⤓ Print / Save as PDF</button>
  <button class="ghost" onclick="window.close()">Close</button>
</div>
<div class="report">{body}
<p class="muted" style="margin-top:40px;font-size:9pt;border-top:1px solid #e2e8f0;padding-top:10px">
Generated {_escape(generated_at)} by the Coder56 Pentest Console · CONFIDENTIAL — Authorized Security Testing.
</p>
</div></body></html>"""


# =============================================================================
# Client-ready report (agent-authored narrative, deterministic layout)
# =============================================================================

RISK_COLORS = {
    "Critical": ("#9f1239", "#fee2e2"),
    "High":     ("#9a3412", "#ffedd5"),
    "Medium":   ("#854d0e", "#fef9c3"),
    "Low":      ("#166534", "#dcfce7"),
}


def _risk_badge(risk: str) -> str:
    r = (risk or "").strip().capitalize()
    if r not in RISK_COLORS:
        r = "Medium"
    fg, bg = RISK_COLORS[r]
    return f'<span class="sev" style="background:{bg};color:{fg}">Overall risk: {r}</span>'


def _meta_row(label: str, val_md: str) -> str:
    dd = _md(val_md) if (val_md or "").strip() else '<span class="muted">—</span>'
    return f"<dt>{_escape(label)}</dt><dd>{dd}</dd>"


def _client_exec_summary(report: Dict[str, Any], tally: Dict[str, int]) -> str:
    total = sum(tally.values())
    chips = ''.join(
        f'<span class="chip" style="background:{SEV_COLORS[s][1]};color:{SEV_COLORS[s][0]}">'
        f'{tally[s]} {s.upper()}</span>' for s in SEV_ORDER if tally.get(s))
    parts = [f"<p>{_md(report.get('executive_summary'))}</p>",
             f"<p>{_risk_badge(report.get('overall_risk'))}</p>"]
    if report.get("overall_risk_rationale"):
        parts.append(f"<p><b>Risk rationale.</b> {_md(report.get('overall_risk_rationale'))}</p>")
    if chips:
        parts.append(f'<div class="tally">{chips}'
                     f'<span class="chip" style="background:#e2e8f0;color:#334155">{total} TOTAL</span></div>')
    return f'<section><h2 class="sec">1. Executive Summary</h2>{"".join(parts)}</section>'


def _client_scope(eng: Dict[str, Any]) -> str:
    return f"""
<section><h2 class="sec">2. Scope &amp; Rules of Engagement</h2>
  <h3>Authorized scope</h3><p class="mono">{_escape(eng.get('target_scope') or '—')}</p>
  <h3>Rules of engagement</h3><p>{_md(eng.get('roe')) or '<span class="muted">—</span>'}</p>
</section>"""


def _client_methodology(report: Dict[str, Any]) -> str:
    md = report.get("methodology_summary")
    if not md:
        return ""
    return f'<section><h2 class="sec">3. Methodology</h2>{_md(md)}</section>'


def _client_findings(findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return ('<section><h2 class="sec">5. Findings</h2>'
                '<div class="note">No findings documented.</div></section>')
    cards = []
    for n, f in enumerate(findings, 1):
        sev = (f.get("severity") or "info").lower()
        cvss = f.get("cvss")
        cvss = f"{float(cvss):.1f}" if _is_num(cvss) else "—"
        oid = f.get("owasp_id")
        oid_html = f'<span class="owasp">OWASP {_escape(oid)}</span>' if oid else ""
        cards.append(f"""
<div class="finding" style="border-left-color:{SEV_COLORS.get(sev, SEV_COLORS['info'])[0]}">
  <div class="head">
    <span class="t">[{n}] {_escape(f.get('title') or 'Untitled')}</span>
    {_sev_badge(sev)} <span class="muted">CVSS {cvss}</span> {_verified_badge(f)}{oid_html}
  </div>
  <div class="asset"><b>Affected asset:</b> {_escape(f.get('affected_asset') or '—')}</div>
  <dl class="meta">
    {_meta_row('What it is', f.get('what_it_is'))}
    {_meta_row('Why it matters', f.get('business_impact'))}
    {_meta_row('How we proved it', f.get('proof'))}
    {_meta_row('How to fix', f.get('remediation'))}
  </dl>
</div>""")
    return f'<section><h2 class="sec">5. Findings</h2>{"".join(cards)}</section>'


def _client_conclusion(report: Dict[str, Any]) -> str:
    c = report.get("conclusion")
    if not c:
        return ""
    return f'<section><h2 class="sec">6. Conclusion</h2>{_md(c)}</section>'


def render_client_report(engagement: Dict[str, Any], report: Dict[str, Any],
                         runs: List[Dict[str, Any]], mitre: Dict[str, Any],
                         verdicts_by_run: Dict[str, List[Dict[str, Any]]]) -> str:
    """Build the client-ready HTML report from the report-writer agent's JSON
    (executive summary, overall risk, per-finding What/Impact/Proof/Fix prose)
    with the same print-ready shell as the deterministic report."""
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    findings = report.get("findings") or []
    order = {s: i for i, s in enumerate(SEV_ORDER)}
    findings = sorted(findings, key=lambda f: order.get((f.get("severity") or "info").lower(), 99))
    tally = _findings_tally(findings)
    body = (
        _cover(engagement, tally, generated_at)
        + _client_exec_summary(report, tally)
        + _client_scope(engagement)
        + _client_methodology(report)
        + _owasp_coverage(engagement, findings, number="4")
        + _client_findings(findings)
        + _client_conclusion(report)
        + _appendix(runs, verdicts_by_run)
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_escape(engagement.get('name') or 'Engagement')} — Penetration Test Report</title>
<style>{_CSS}</style></head>
<body>
<div class="toolbar no-print">
  <span class="tb-title">◆ Penetration Test Report · {_escape(engagement.get('name') or '')}</span>
  <span class="spacer"></span>
  <button onclick="window.print()">⤓ Print / Save as PDF</button>
  <button class="ghost" onclick="window.close()">Close</button>
</div>
<div class="report">{body}
<p class="muted" style="margin-top:40px;font-size:9pt;border-top:1px solid #e2e8f0;padding-top:10px">
Generated {_escape(generated_at)} by the Coder56 Pentest Console · CONFIDENTIAL — Authorized Security Testing.
</p>
</div></body></html>"""
