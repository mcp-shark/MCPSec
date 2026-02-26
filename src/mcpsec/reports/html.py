"""MCPSec — Interactive HTML Dashboard Report.

Generates a self-contained HTML security dashboard with:
    - Cybersecurity dark theme
    - Chart.js interactive charts (severity donut, OWASP radar, framework bars)
    - Sortable/filterable findings table
    - Expandable finding details with code examples
    - Executive summary with compliance scorecard
    - LLM analysis callout (when available)

Single-file output — no external dependencies at runtime (Chart.js via CDN).
"""

from __future__ import annotations

import html
import json
from typing import Optional

from mcpsec.models.findings import Finding, ScanResult, Severity
from mcpsec.reports.scorecard import ScoreCard


# ---------------------------------------------------------------------------
# Severity theme colors (cybersecurity palette)
# ---------------------------------------------------------------------------

_SEVERITY_COLORS = {
    Severity.CRITICAL: "#ff1744",
    Severity.HIGH: "#ff9100",
    Severity.MEDIUM: "#ffd600",
    Severity.LOW: "#448aff",
    Severity.INFORMATIONAL: "#69f0ae",
}

_SEVERITY_BG = {
    Severity.CRITICAL: "rgba(255,23,68,0.15)",
    Severity.HIGH: "rgba(255,145,0,0.15)",
    Severity.MEDIUM: "rgba(255,214,0,0.15)",
    Severity.LOW: "rgba(68,138,255,0.15)",
    Severity.INFORMATIONAL: "rgba(105,240,174,0.15)",
}

_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFORMATIONAL,
]

_GRADE_COLORS = {
    "A": "#69f0ae",
    "B": "#ffd600",
    "C": "#ff9100",
    "D": "#ff6e40",
    "F": "#ff1744",
}


def generate_html_report(
    result: ScanResult,
    scorecard: Optional[ScoreCard] = None,
) -> str:
    """Generate a self-contained interactive HTML dashboard report.

    Args:
        result: Completed scan result.
        scorecard: Optional compliance scorecard (for framework scores + LLM analysis).

    Returns:
        Complete HTML document as a string.
    """
    target = html.escape(result.target_url or result.target_path or "unknown")
    counts = result.finding_count
    total = len(result.findings)
    gate = "PASSED" if result.passed_ci_gate else "FAILED"
    gate_class = "pass" if result.passed_ci_gate else "fail"

    # Scorecard defaults
    overall_score = scorecard.overall_score if scorecard else _fallback_score(result)
    grade = scorecard.grade if scorecard else _fallback_grade(result)
    grade_color = _GRADE_COLORS.get(grade, "#69f0ae")
    mcp_score = scorecard.mcp_spec_score if scorecard else overall_score
    owasp_coverage = scorecard.owasp_mcp_coverage if scorecard else 0
    fastmcp_score = scorecard.fastmcp_baseline_score if scorecard else overall_score
    analysis = scorecard.analysis if scorecard else None

    # Chart data
    severity_data = json.dumps([counts[s] for s in _SEVERITY_ORDER])
    severity_labels = json.dumps([s.value.capitalize() for s in _SEVERITY_ORDER])
    severity_colors = json.dumps([_SEVERITY_COLORS[s] for s in _SEVERITY_ORDER])

    # OWASP radar data
    owasp_labels, owasp_data = _build_owasp_radar_data(result, scorecard)

    # Framework bar data
    framework_scores = json.dumps([mcp_score, owasp_coverage * 10, fastmcp_score])

    # Findings HTML
    findings_html = _build_findings_html(result)

    # Remediation table
    remediation_html = _build_remediation_html(result)

    # Standards cross-reference
    standards_html = _build_standards_html(result)

    # Auditor breakdown
    auditor_html = _build_auditor_html(scorecard)

    # Analysis section
    analysis_html = ""
    if analysis:
        analysis_html = f"""
        <div class="analysis-box">
            <h3>🤖 AI Risk Analysis</h3>
            <p>{html.escape(analysis)}</p>
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCPSec Report — {target}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
    <style>
{_CSS}
    </style>
</head>
<body>
    <!-- Executive Banner -->
    <header class="banner">
        <div class="banner-left">
            <h1>🛡️ MCPSec Security Report</h1>
            <p class="target"><code>{target}</code></p>
            <p class="meta">
                Scan ID: <code>{html.escape(result.scan_id)}</code> |
                {result.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')} |
                {result.scan_duration_seconds}s |
                {result.access_level.value} / {result.depth.value}
            </p>
        </div>
        <div class="banner-right">
            <div class="grade-circle" style="border-color: {grade_color}">
                <span class="grade-letter" style="color: {grade_color}">{grade}</span>
                <span class="grade-score">{overall_score}/100</span>
            </div>
            <div class="gate-badge {gate_class}">{gate}</div>
        </div>
    </header>

    <!-- Summary Cards -->
    <section class="cards">
        <div class="card severity-critical">
            <span class="card-num">{counts[Severity.CRITICAL]}</span>
            <span class="card-label">Critical</span>
        </div>
        <div class="card severity-high">
            <span class="card-num">{counts[Severity.HIGH]}</span>
            <span class="card-label">High</span>
        </div>
        <div class="card severity-medium">
            <span class="card-num">{counts[Severity.MEDIUM]}</span>
            <span class="card-label">Medium</span>
        </div>
        <div class="card severity-low">
            <span class="card-num">{counts[Severity.LOW]}</span>
            <span class="card-label">Low</span>
        </div>
        <div class="card severity-info">
            <span class="card-num">{counts[Severity.INFORMATIONAL]}</span>
            <span class="card-label">Info</span>
        </div>
        <div class="card card-total">
            <span class="card-num">{total}</span>
            <span class="card-label">Total</span>
        </div>
        <div class="card card-cvss">
            <span class="card-num">{result.max_cvss}</span>
            <span class="card-label">Max CVSS</span>
        </div>
    </section>

    {analysis_html}

    <!-- Charts Row -->
    <section class="charts-row">
        <div class="chart-container">
            <h3>Severity Distribution</h3>
            <canvas id="severityChart"></canvas>
        </div>
        <div class="chart-container">
            <h3>OWASP MCP Top 10 Coverage</h3>
            <canvas id="owaspChart"></canvas>
        </div>
        <div class="chart-container">
            <h3>Framework Compliance</h3>
            <canvas id="frameworkChart"></canvas>
        </div>
    </section>

    {auditor_html}

    <!-- Findings -->
    <section class="findings-section">
        <h2>Findings</h2>
        <div class="filter-bar">
            <input type="text" id="findingSearch" placeholder="Search findings..." onkeyup="filterFindings()">
            <select id="severityFilter" onchange="filterFindings()">
                <option value="">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="informational">Info</option>
            </select>
        </div>
        <div id="findingsContainer">
            {findings_html}
        </div>
    </section>

    <!-- Remediation Priorities -->
    <section class="remediation-section">
        <h2>Remediation Priorities</h2>
        {remediation_html}
    </section>

    <!-- Standards Cross-Reference -->
    <section class="standards-section">
        <details>
            <summary><h2 style="display:inline">Standards Cross-Reference</h2></summary>
            {standards_html}
        </details>
    </section>

    <!-- Footer -->
    <footer>
        <p>Generated by MCPSec v{result.scanner_version} — MCP Security Scanner |
           Spec: {result.spec_version}</p>
    </footer>

    <script>
{_chart_js(severity_labels, severity_data, severity_colors, owasp_labels, owasp_data, framework_scores)}
{_FILTER_JS}
    </script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Findings HTML builder
# ---------------------------------------------------------------------------

def _build_findings_html(result: ScanResult) -> str:
    if not result.findings:
        return '<p class="no-findings">No findings. ✅</p>'

    rows = []
    for f in sorted(result.findings, key=lambda x: (-x.cvss_score, x.finding_id)):
        color = _SEVERITY_COLORS[f.severity]
        bg = _SEVERITY_BG[f.severity]
        code_html = ""
        if f.code_example:
            code_html = f'<pre class="code-example"><code>{html.escape(f.code_example)}</code></pre>'

        standards_list = "".join(
            f"<li><code>{html.escape(s.id)}</code>: {html.escape(s.section)}</li>"
            for s in f.standards
        )

        rows.append(f"""
        <div class="finding-card" data-severity="{f.severity.value}" style="border-left: 4px solid {color}">
            <div class="finding-header" onclick="this.parentElement.classList.toggle('expanded')">
                <span class="finding-id" style="color:{color}">{html.escape(f.finding_id)}</span>
                <span class="finding-title">{html.escape(f.title)}</span>
                <span class="finding-badges">
                    <span class="badge" style="background:{bg};color:{color}">{f.severity.value.upper()}</span>
                    <span class="badge cvss-badge">CVSS {f.cvss_score}</span>
                    <span class="badge">{f.confidence.value}</span>
                </span>
                <span class="expand-icon">▶</span>
            </div>
            <div class="finding-details">
                <table class="detail-table">
                    <tr><td>CWE</td><td>{html.escape(f.cwe_id)} — {html.escape(f.cwe_name)}</td></tr>
                    <tr><td>Detection</td><td>{f.detection_mode.value}</td></tr>
                    <tr><td>Effort</td><td>{f.remediation_effort.value}</td></tr>
                    <tr><td>CVSS Vector</td><td><code>{html.escape(f.cvss_vector or 'N/A')}</code></td></tr>
                </table>
                <div class="detail-section">
                    <h4>Evidence</h4>
                    <div class="evidence-box">{html.escape(f.evidence)}</div>
                </div>
                <div class="detail-section">
                    <h4>Risk</h4>
                    <p>{html.escape(f.risk)}</p>
                </div>
                <div class="detail-section">
                    <h4>Recommendation</h4>
                    <p>{html.escape(f.recommendation)}</p>
                </div>
                {code_html}
                <div class="detail-section">
                    <h4>Standards</h4>
                    <ul>{standards_list}</ul>
                </div>
            </div>
        </div>""")

    return "\n".join(rows)


# ---------------------------------------------------------------------------
# Remediation table
# ---------------------------------------------------------------------------

def _build_remediation_html(result: ScanResult) -> str:
    if not result.findings:
        return '<p class="no-findings">No remediation needed. ✅</p>'

    sorted_findings = sorted(
        result.findings,
        key=lambda f: (f.remediation_priority or 999, -f.cvss_score),
    )

    rows = []
    for i, f in enumerate(sorted_findings, 1):
        color = _SEVERITY_COLORS[f.severity]
        action = html.escape(f.recommendation[:100])
        if len(f.recommendation) > 100:
            action += "..."
        rows.append(f"""
            <tr>
                <td>{i}</td>
                <td style="color:{color}">{html.escape(f.finding_id)}</td>
                <td><span class="badge" style="background:{_SEVERITY_BG[f.severity]};color:{color}">{f.severity.value}</span></td>
                <td>{f.cvss_score}</td>
                <td>{f.remediation_effort.value}</td>
                <td>{action}</td>
            </tr>""")

    return f"""
    <table class="data-table">
        <thead>
            <tr><th>#</th><th>Finding</th><th>Severity</th><th>CVSS</th><th>Effort</th><th>Action</th></tr>
        </thead>
        <tbody>{"".join(rows)}</tbody>
    </table>"""


# ---------------------------------------------------------------------------
# Standards cross-reference
# ---------------------------------------------------------------------------

def _build_standards_html(result: ScanResult) -> str:
    if not result.findings:
        return ""

    std_map: dict[str, set[str]] = {}
    for f in result.findings:
        for s in f.standards:
            std_map.setdefault(s.id, set()).add(f.finding_id)

    rows = []
    for std_id in sorted(std_map.keys()):
        ids = ", ".join(sorted(std_map[std_id]))
        rows.append(f"<tr><td><code>{html.escape(std_id)}</code></td><td>{html.escape(ids)}</td></tr>")

    return f"""
    <table class="data-table">
        <thead><tr><th>Standard</th><th>Findings</th></tr></thead>
        <tbody>{"".join(rows)}</tbody>
    </table>"""


# ---------------------------------------------------------------------------
# Auditor breakdown
# ---------------------------------------------------------------------------

def _build_auditor_html(scorecard: Optional[ScoreCard]) -> str:
    if not scorecard or not scorecard.auditor_breakdown:
        return ""

    rows = []
    for a in scorecard.auditor_breakdown:
        rows.append(f"""
            <tr>
                <td>{html.escape(a.auditor)}</td>
                <td>{a.finding_count}</td>
                <td>{a.max_cvss}</td>
                <td>{a.score}/100</td>
            </tr>""")

    return f"""
    <section class="auditor-section">
        <h2>Auditor Breakdown</h2>
        <table class="data-table">
            <thead><tr><th>Auditor</th><th>Findings</th><th>Max CVSS</th><th>Score</th></tr></thead>
            <tbody>{"".join(rows)}</tbody>
        </table>
    </section>"""


# ---------------------------------------------------------------------------
# OWASP radar data
# ---------------------------------------------------------------------------

def _build_owasp_radar_data(
    result: ScanResult, scorecard: Optional[ScoreCard]
) -> tuple[str, str]:
    from mcpsec.reports.scorecard import _OWASP_MCP_CATEGORIES, _compute_owasp_coverage

    if scorecard and scorecard.owasp_categories:
        labels = [f"MCP{i:02d}" for i in range(1, 11)]
        data = [100 if c.clear else 0 for c in scorecard.owasp_categories]
    else:
        _, categories = _compute_owasp_coverage(result.findings)
        labels = [c.id for c in categories]
        data = [100 if c.clear else 0 for c in categories]

    return json.dumps(labels), json.dumps(data)


# ---------------------------------------------------------------------------
# Fallback scoring (when no scorecard provided)
# ---------------------------------------------------------------------------

def _fallback_score(result: ScanResult) -> int:
    from mcpsec.reports.scorecard import _compute_score
    return _compute_score(result.findings)


def _fallback_grade(result: ScanResult) -> str:
    from mcpsec.reports.scorecard import _compute_grade
    grade, _ = _compute_grade(_fallback_score(result))
    return grade


# ---------------------------------------------------------------------------
# Chart.js initialization
# ---------------------------------------------------------------------------

def _chart_js(
    severity_labels: str,
    severity_data: str,
    severity_colors: str,
    owasp_labels: str,
    owasp_data: str,
    framework_scores: str,
) -> str:
    return f"""
    // Severity Donut
    new Chart(document.getElementById('severityChart'), {{
        type: 'doughnut',
        data: {{
            labels: {severity_labels},
            datasets: [{{
                data: {severity_data},
                backgroundColor: {severity_colors},
                borderColor: '#0a0e17',
                borderWidth: 2
            }}]
        }},
        options: {{
            responsive: true,
            plugins: {{
                legend: {{ position: 'bottom', labels: {{ color: '#c0c8d8' }} }}
            }}
        }}
    }});

    // OWASP Radar
    new Chart(document.getElementById('owaspChart'), {{
        type: 'radar',
        data: {{
            labels: {owasp_labels},
            datasets: [{{
                label: 'Coverage',
                data: {owasp_data},
                fill: true,
                backgroundColor: 'rgba(105,240,174,0.2)',
                borderColor: '#69f0ae',
                pointBackgroundColor: '#69f0ae',
                pointBorderColor: '#0a0e17',
            }}]
        }},
        options: {{
            responsive: true,
            scales: {{
                r: {{
                    beginAtZero: true,
                    max: 100,
                    ticks: {{ color: '#8892a4', stepSize: 50 }},
                    grid: {{ color: 'rgba(255,255,255,0.08)' }},
                    angleLines: {{ color: 'rgba(255,255,255,0.08)' }},
                    pointLabels: {{ color: '#c0c8d8', font: {{ size: 11 }} }}
                }}
            }},
            plugins: {{
                legend: {{ display: false }}
            }}
        }}
    }});

    // Framework Bar
    new Chart(document.getElementById('frameworkChart'), {{
        type: 'bar',
        data: {{
            labels: ['MCP Spec', 'OWASP MCP', 'FastMCP'],
            datasets: [{{
                label: 'Score',
                data: {framework_scores},
                backgroundColor: ['#448aff', '#69f0ae', '#ffd600'],
                borderColor: '#0a0e17',
                borderWidth: 1,
                borderRadius: 4,
            }}]
        }},
        options: {{
            responsive: true,
            indexAxis: 'y',
            scales: {{
                x: {{
                    beginAtZero: true,
                    max: 100,
                    ticks: {{ color: '#8892a4' }},
                    grid: {{ color: 'rgba(255,255,255,0.06)' }}
                }},
                y: {{
                    ticks: {{ color: '#c0c8d8' }},
                    grid: {{ display: false }}
                }}
            }},
            plugins: {{
                legend: {{ display: false }}
            }}
        }}
    }});
    """


# ---------------------------------------------------------------------------
# Filter/search JavaScript
# ---------------------------------------------------------------------------

_FILTER_JS = """
    function filterFindings() {
        const query = document.getElementById('findingSearch').value.toLowerCase();
        const severity = document.getElementById('severityFilter').value;
        document.querySelectorAll('.finding-card').forEach(card => {
            const text = card.textContent.toLowerCase();
            const sev = card.dataset.severity;
            const matchQuery = !query || text.includes(query);
            const matchSev = !severity || sev === severity;
            card.style.display = (matchQuery && matchSev) ? '' : 'none';
        });
    }
"""


# ---------------------------------------------------------------------------
# CSS — Cybersecurity dark theme
# ---------------------------------------------------------------------------

_CSS = """
    * { margin: 0; padding: 0; box-sizing: border-box; }

    body {
        background: #0a0e17;
        color: #c0c8d8;
        font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
        line-height: 1.6;
        padding: 24px;
        max-width: 1400px;
        margin: 0 auto;
    }

    code, pre { font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace; }

    /* Banner */
    .banner {
        display: flex;
        justify-content: space-between;
        align-items: center;
        background: linear-gradient(135deg, #111827 0%, #0f1729 100%);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 12px;
        padding: 28px 32px;
        margin-bottom: 24px;
    }
    .banner h1 { color: #e2e8f0; font-size: 1.6rem; margin-bottom: 8px; }
    .banner .target code { color: #69f0ae; font-size: 1rem; }
    .banner .meta { color: #6b7a90; font-size: 0.85rem; margin-top: 6px; }
    .banner-right { display: flex; align-items: center; gap: 20px; }

    .grade-circle {
        width: 90px; height: 90px;
        border: 3px solid;
        border-radius: 50%;
        display: flex; flex-direction: column;
        align-items: center; justify-content: center;
    }
    .grade-letter { font-size: 2rem; font-weight: 800; }
    .grade-score { font-size: 0.75rem; color: #8892a4; }

    .gate-badge {
        padding: 8px 18px;
        border-radius: 6px;
        font-weight: 700;
        font-size: 0.9rem;
        text-transform: uppercase;
    }
    .gate-badge.pass { background: rgba(105,240,174,0.15); color: #69f0ae; }
    .gate-badge.fail { background: rgba(255,23,68,0.15); color: #ff1744; }

    /* Summary Cards */
    .cards {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
        gap: 12px;
        margin-bottom: 24px;
    }
    .card {
        background: #111827;
        border: 1px solid rgba(255,255,255,0.06);
        border-radius: 10px;
        padding: 18px;
        text-align: center;
    }
    .card-num { display: block; font-size: 2rem; font-weight: 800; }
    .card-label { display: block; font-size: 0.8rem; color: #6b7a90; text-transform: uppercase; letter-spacing: 0.05em; }
    .severity-critical .card-num { color: #ff1744; }
    .severity-high .card-num { color: #ff9100; }
    .severity-medium .card-num { color: #ffd600; }
    .severity-low .card-num { color: #448aff; }
    .severity-info .card-num { color: #69f0ae; }
    .card-total .card-num { color: #e2e8f0; }
    .card-cvss .card-num { color: #ff6e40; }

    /* Analysis Box */
    .analysis-box {
        background: linear-gradient(135deg, rgba(105,240,174,0.08), rgba(68,138,255,0.08));
        border: 1px solid rgba(105,240,174,0.2);
        border-radius: 10px;
        padding: 20px 24px;
        margin-bottom: 24px;
    }
    .analysis-box h3 { color: #69f0ae; margin-bottom: 10px; }
    .analysis-box p { color: #c0c8d8; line-height: 1.7; }

    /* Charts */
    .charts-row {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 16px;
        margin-bottom: 24px;
    }
    .chart-container {
        background: #111827;
        border: 1px solid rgba(255,255,255,0.06);
        border-radius: 10px;
        padding: 20px;
    }
    .chart-container h3 { color: #e2e8f0; font-size: 0.95rem; margin-bottom: 12px; }

    /* Sections */
    h2 {
        color: #e2e8f0;
        font-size: 1.3rem;
        margin-bottom: 16px;
        padding-bottom: 8px;
        border-bottom: 1px solid rgba(255,255,255,0.08);
    }
    section { margin-bottom: 32px; }

    /* Data Tables */
    .data-table {
        width: 100%;
        border-collapse: collapse;
        background: #111827;
        border-radius: 8px;
        overflow: hidden;
    }
    .data-table th {
        background: #1a2233;
        color: #8892a4;
        text-transform: uppercase;
        font-size: 0.75rem;
        letter-spacing: 0.05em;
        padding: 12px 16px;
        text-align: left;
    }
    .data-table td {
        padding: 10px 16px;
        border-bottom: 1px solid rgba(255,255,255,0.04);
        font-size: 0.9rem;
    }
    .data-table tr:hover { background: rgba(255,255,255,0.02); }

    /* Badges */
    .badge {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.03em;
    }
    .cvss-badge { background: rgba(255,110,64,0.15); color: #ff6e40; }

    /* Filter Bar */
    .filter-bar {
        display: flex;
        gap: 12px;
        margin-bottom: 16px;
    }
    .filter-bar input, .filter-bar select {
        background: #1a2233;
        border: 1px solid rgba(255,255,255,0.1);
        color: #c0c8d8;
        padding: 10px 14px;
        border-radius: 6px;
        font-size: 0.9rem;
    }
    .filter-bar input { flex: 1; }
    .filter-bar input::placeholder { color: #4a5568; }

    /* Finding Cards */
    .finding-card {
        background: #111827;
        border: 1px solid rgba(255,255,255,0.06);
        border-radius: 8px;
        margin-bottom: 8px;
        overflow: hidden;
    }
    .finding-header {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 14px 18px;
        cursor: pointer;
        transition: background 0.15s;
    }
    .finding-header:hover { background: rgba(255,255,255,0.02); }
    .finding-id { font-weight: 700; font-family: monospace; min-width: 140px; }
    .finding-title { flex: 1; color: #e2e8f0; }
    .finding-badges { display: flex; gap: 6px; }
    .expand-icon {
        color: #4a5568;
        font-size: 0.8rem;
        transition: transform 0.2s;
    }
    .finding-card.expanded .expand-icon { transform: rotate(90deg); }
    .finding-details {
        display: none;
        padding: 0 18px 18px;
        border-top: 1px solid rgba(255,255,255,0.04);
    }
    .finding-card.expanded .finding-details { display: block; }

    .detail-table { margin: 12px 0; }
    .detail-table td { padding: 4px 12px 4px 0; }
    .detail-table td:first-child { color: #6b7a90; font-size: 0.85rem; white-space: nowrap; }

    .detail-section { margin: 14px 0; }
    .detail-section h4 { color: #8892a4; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px; }

    .evidence-box {
        background: #0d1117;
        border: 1px solid rgba(255,255,255,0.06);
        border-radius: 6px;
        padding: 12px;
        font-family: monospace;
        font-size: 0.85rem;
        white-space: pre-wrap;
        word-break: break-word;
        color: #a0aec0;
    }

    .code-example {
        background: #0d1117;
        border: 1px solid rgba(105,240,174,0.15);
        border-radius: 6px;
        padding: 14px;
        margin: 12px 0;
        overflow-x: auto;
        font-size: 0.85rem;
        color: #69f0ae;
    }

    .no-findings { color: #69f0ae; font-size: 1.1rem; text-align: center; padding: 40px; }

    /* Footer */
    footer {
        text-align: center;
        padding: 24px;
        color: #4a5568;
        font-size: 0.8rem;
        border-top: 1px solid rgba(255,255,255,0.04);
    }

    /* Responsive */
    @media (max-width: 900px) {
        .charts-row { grid-template-columns: 1fr; }
        .banner { flex-direction: column; gap: 16px; }
        .cards { grid-template-columns: repeat(3, 1fr); }
    }

    details summary { cursor: pointer; }
    details summary h2 { display: inline; border: none; padding: 0; margin: 0; }
"""

