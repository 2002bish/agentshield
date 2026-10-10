import html
import json
from typing import Any


def render_html_report(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    metadata = report.get("metadata", {})
    findings = report.get("findings", [])
    finding_cards = []
    for finding in findings:
        severity = html.escape(str(finding.get("severity", "info")).upper())
        finding_cards.append(
            "<article class='finding'>"
            f"<h2>{html.escape(str(finding.get('attack_name', 'Finding')))} "
            f"<span class='severity'>{severity}</span></h2>"
            f"<p>{html.escape(str(finding.get('description', '')))}</p>"
            f"<p><strong>Status:</strong> {html.escape(str(finding.get('status', 'unknown')))} "
            f"| <strong>Score:</strong> {html.escape(str(finding.get('score', 0)))}</p>"
            f"<p><strong>Evidence:</strong> {html.escape(str(finding.get('evidence', '')))}</p>"
            f"<p><strong>Recommendation:</strong> {html.escape(str(finding.get('fix', '')))}</p>"
            "</article>"
        )
    report_json = html.escape(json.dumps(report, indent=2, ensure_ascii=False))
    safety_score = summary.get("overall_safety_score_percentage")
    score_display = "Not available (scan incomplete)" if safety_score is None else f"{safety_score}%"
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>AgentShield security test report</title>"
        "<style>body{font:16px system-ui;max-width:960px;margin:2rem auto;padding:0 1rem;"
        "color:#17202a}article{border:1px solid #ccd1d1;border-radius:8px;padding:1rem;"
        "margin:1rem 0}.severity{font-size:.8em;color:#922b21}pre{white-space:pre-wrap;"
        "overflow-wrap:anywhere;background:#f4f6f7;padding:1rem}</style></head><body>"
        "<h1>AgentShield security test report</h1>"
        f"<p>Generated: {html.escape(str(metadata.get('timestamp', '')))}</p>"
        f"<p>Scan status: {html.escape(str(summary.get('status', 'unknown')))} | "
        f"Modules tested: {html.escape(str(summary.get('modules_tested', 0)))} | "
        f"Findings: {html.escape(str(summary.get('vulnerable_modules_count', 0)))} | "
        f"Safety score: {html.escape(score_display)}</p>"
        + "".join(finding_cards)
        + f"<details><summary>Full report data</summary><pre>{report_json}</pre></details>"
        + "</body></html>"
    )