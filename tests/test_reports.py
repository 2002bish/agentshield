from agentshield.attacks.base import Finding, Severity
from agentshield.report.formatters import render_html_report
from agentshield.service.schemas import ScanCreateRequest


def test_findings_get_unique_agentshield_ids():
    first = Finding("Injection", Severity.INFO, 0, "", "", "")
    second = Finding("Injection", Severity.INFO, 0, "", "", "")

    assert first.finding_id.startswith("AS-")
    assert first.finding_id != second.finding_id


def test_finding_preserves_positional_identifier_and_timestamp_arguments():
    finding = Finding(
        "Injection", Severity.INFO, 0, "", "", "", "", "", "", "AS-LEGACY", "timestamp"
    )

    assert finding.finding_id == "AS-LEGACY"
    assert finding.timestamp == "timestamp"
    assert finding.status == "completed"


def test_html_report_escapes_untrusted_finding_content():
    report = {
        "metadata": {"timestamp": "2026-10-10T00:00:00+00:00"},
        "summary": {
            "status": "completed",
            "modules_tested": 1,
            "vulnerable_modules_count": 1,
            "overall_safety_score_percentage": 0,
        },
        "findings": [
            {
                "attack_name": "<script>alert(1)</script>",
                "severity": "high",
                "description": "<img src=x onerror=alert(1)>",
                "status": "completed",
                "score": 10,
                "evidence": "<script>payload</script>",
                "fix": "<iframe src=evil>",
            }
        ],
    }

    document = render_html_report(report)

    assert "<script>alert(1)</script>" not in document
    assert "<img src=x" not in document
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in document
    assert "&lt;iframe src=evil&gt;" in document


def test_scan_request_requires_explicit_authorization():
    request = ScanCreateRequest(
        name="staging",
        endpoint_url="https://agent.example.com/chat",
        model="test-model",
        api_key="test-key",
    )
    assert request.authorized is False
    with_authorization = request.model_copy(update={"authorized": True})
    assert with_authorization.authorized is True
