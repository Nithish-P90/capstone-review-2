# dashboard/report_generator.py

import html
import os
import webbrowser
from collections import defaultdict
from datetime import datetime

# ─── Severity colours ──────────────────────────────────────
_SEVERITY_COLORS = {
    "CRITICAL": ("#ff4444", "#ffffff"),
    "HIGH":     ("#ff8c00", "#ffffff"),
    "MEDIUM":   ("#f0ad4e", "#0d1117"),
    "LOW":      ("#3fb950", "#0d1117"),
}

_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    background: #0d1117; color: #c9d1d9;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    font-size: 15px; line-height: 1.6; padding: 32px 24px;
}
h1 { font-size: 1.8rem; color: #e6edf3; margin-bottom: 4px; }
.meta { color: #8b949e; font-size: 0.9rem; margin-bottom: 32px; }
.meta span { margin-right: 24px; }

/* Summary cards */
.summary { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 40px; }
.stat-card {
    background: #161b22; border: 1px solid #30363d; border-radius: 8px;
    padding: 16px 24px; min-width: 140px; text-align: center;
}
.stat-card .number { font-size: 2rem; font-weight: 700; color: #e6edf3; }
.stat-card .label  { font-size: 0.8rem; color: #8b949e; text-transform: uppercase; letter-spacing: 0.05em; }
.stat-card.critical .number { color: #ff4444; }
.stat-card.high     .number { color: #ff8c00; }
.stat-card.medium   .number { color: #f0ad4e; }
.stat-card.low      .number { color: #3fb950; }

/* Findings */
h2.section-title { font-size: 1.2rem; color: #8b949e; margin-bottom: 16px;
                   text-transform: uppercase; letter-spacing: 0.06em; }
.finding-card {
    background: #161b22; border: 1px solid #30363d; border-radius: 10px;
    margin-bottom: 24px; overflow: hidden;
}
.card-header {
    display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
    padding: 14px 20px; border-bottom: 1px solid #30363d;
    background: #1c2128;
}
.func-name { font-size: 1.05rem; font-weight: 600; color: #79c0ff; font-family: monospace; }
.badge {
    border-radius: 4px; padding: 2px 10px; font-size: 0.78rem;
    font-weight: 700; letter-spacing: 0.04em;
}
.confidence { margin-left: auto; color: #8b949e; font-size: 0.85rem; }
.card-body { padding: 20px; }
.card-body h4 {
    font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.06em;
    color: #8b949e; margin: 20px 0 8px;
}
.card-body h4:first-child { margin-top: 0; }
.description { color: #c9d1d9; }
.explanation { color: #c9d1d9; }
pre.code-block {
    background: #010409; border: 1px solid #30363d; border-radius: 6px;
    padding: 14px 16px; overflow-x: auto;
    font-family: "SFMono-Regular", Consolas, monospace; font-size: 0.85rem;
    color: #58a6ff; white-space: pre-wrap; word-break: break-all;
}
pre.code-block.fixed { color: #3fb950; }
.fix-description { color: #8b949e; font-style: italic; margin-top: 8px; font-size: 0.9rem; }
.cve-list { list-style: none; padding: 0; }
.cve-list li {
    padding: 6px 0; border-bottom: 1px solid #21262d; font-size: 0.88rem;
}
.cve-list li:last-child { border-bottom: none; }
.cve-id { color: #f78166; font-weight: 600; font-family: monospace; }
.no-findings {
    text-align: center; padding: 64px; color: #3fb950;
    font-size: 1.2rem;
}
"""


def _severity_badge(severity: str) -> str:
    bg, fg = _SEVERITY_COLORS.get(severity.upper(), ("#8b949e", "#ffffff"))
    return (
        f'<span class="badge" style="background:{bg};color:{fg}">'
        f'{html.escape(severity)}</span>'
    )


def _build_stats(findings: list) -> dict:
    stats = {"total": len(findings), "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "MEDIUM").upper()
        if sev in stats:
            stats[sev] += 1
    return stats


def _render_cve_list(cve_matches: list) -> str:
    if not cve_matches:
        return "<p style='color:#8b949e;font-size:0.88rem'>No related CVEs retrieved.</p>"
    items = []
    for m in cve_matches[:5]:
        cve_id  = html.escape(m.get("cve_id", "N/A"))
        sev     = html.escape(m.get("severity", "N/A"))
        cvss    = m.get("cvss_score")
        cvss_s  = f", CVSS: {cvss}" if cvss else ""
        desc    = html.escape((m.get("description") or "")[:120])
        items.append(
            f'<li><span class="cve-id">{cve_id}</span> '
            f'<span style="color:#8b949e">({sev}{cvss_s})</span> — {desc}</li>'
        )
    return "<ul class='cve-list'>" + "".join(items) + "</ul>"


def _render_finding_card(finding: dict, index: int) -> str:
    sev        = finding.get("severity", "MEDIUM").upper()
    cwe_id     = html.escape(finding.get("cwe_id", ""))
    func_name  = html.escape(finding.get("function_name", "unknown"))
    confidence = finding.get("confidence", 0.0)
    desc       = html.escape(finding.get("description", ""))
    explanation= html.escape(finding.get("explanation", ""))
    code       = html.escape(finding.get("code", ""))
    fixed_code = html.escape(finding.get("fixed_code", ""))
    fix_desc   = html.escape(finding.get("fix_description", ""))
    start_line = finding.get("start_line", "?")
    end_line   = finding.get("end_line", "?")
    cve_html   = _render_cve_list(finding.get("cve_matches", []))

    return f"""
<div class="finding-card">
  <div class="card-header">
    <span class="func-name">{func_name}()</span>
    {_severity_badge(sev)}
    <span class="badge" style="background:#1f6feb;color:#fff">{cwe_id}</span>
    <span class="confidence">Confidence: {confidence:.0%}</span>
  </div>
  <div class="card-body">
    <h4>What was detected</h4>
    <p class="description">{desc}</p>

    <h4>Vulnerable Code (lines {start_line}–{end_line})</h4>
    <pre class="code-block">{code}</pre>

    <h4>Why it's vulnerable</h4>
    <p class="explanation">{explanation}</p>

    <h4>Suggested Fix</h4>
    <pre class="code-block fixed">{fixed_code}</pre>
    <p class="fix-description">{fix_desc}</p>

    <h4>Related CVEs</h4>
    {cve_html}
  </div>
</div>"""


def _render_html(findings: list, scan_meta: dict, stats: dict) -> str:
    file_path = html.escape(scan_meta.get("file_path", "unknown"))
    n_funcs   = scan_meta.get("functions_scanned", 0)
    timestamp = html.escape(scan_meta.get("scan_timestamp", datetime.now().isoformat()))

    summary_cards = f"""
<div class="summary">
  <div class="stat-card">
    <div class="number">{n_funcs}</div>
    <div class="label">Functions Scanned</div>
  </div>
  <div class="stat-card">
    <div class="number">{stats['total']}</div>
    <div class="label">Vulnerabilities Found</div>
  </div>
  <div class="stat-card critical">
    <div class="number">{stats['CRITICAL']}</div>
    <div class="label">Critical</div>
  </div>
  <div class="stat-card high">
    <div class="number">{stats['HIGH']}</div>
    <div class="label">High</div>
  </div>
  <div class="stat-card medium">
    <div class="number">{stats['MEDIUM']}</div>
    <div class="label">Medium</div>
  </div>
  <div class="stat-card low">
    <div class="number">{stats['LOW']}</div>
    <div class="label">Low</div>
  </div>
</div>"""

    if not findings:
        findings_html = '<div class="no-findings">✅ No vulnerabilities detected — clean scan!</div>'
    else:
        # Sort: CRITICAL first, then HIGH, MEDIUM, LOW
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_findings = sorted(
            findings,
            key=lambda f: order.get(f.get("severity", "MEDIUM").upper(), 9)
        )
        findings_html = "\n".join(
            _render_finding_card(f, i) for i, f in enumerate(sorted_findings)
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Scan — {file_path}</title>
  <style>{_CSS}</style>
</head>
<body>
  <h1>🔍 Security Scan Report</h1>
  <div class="meta">
    <span>📄 {file_path}</span>
    <span>🕐 {timestamp}</span>
  </div>
  {summary_cards}
  <h2 class="section-title">Vulnerability Details</h2>
  {findings_html}
</body>
</html>"""


def generate_report(findings: list, scan_meta: dict) -> str:
    """
    Generate a self-contained HTML report and open it in the default browser.

    Returns the absolute path to scan_report.html.
    """
    stats       = _build_stats(findings)
    html_content = _render_html(findings, scan_meta, stats)

    output_path = os.path.join(os.getcwd(), "scan_report.html")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    webbrowser.open(f"file://{output_path}")
    return output_path
