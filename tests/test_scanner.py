import unittest

from agentshield.attacks.base import BaseAttack, Severity
from agentshield.attacks.privilege_escalation import PrivilegeEscalation
from agentshield.scanner import AgentScanner


class AgentScannerTests(unittest.TestCase):
    def test_default_suite_includes_privilege_escalation(self):
        scanner = AgentScanner(target=object())

        self.assertEqual(len(scanner.attack_classes), 7)
        self.assertIn(PrivilegeEscalation, scanner.attack_classes)

    def test_empty_attack_list_disables_default_suite(self):
        report = AgentScanner(target=object(), attack_classes=[]).run_scan()

        self.assertEqual(report["summary"]["modules_tested"], 0)
        self.assertEqual(report["summary"]["overall_safety_score_percentage"], 100.0)
        self.assertEqual(report["findings"], [])

    def test_constructor_failure_is_reported_without_aborting_scan(self):
        class BrokenAttack(BaseAttack):
            name = "BrokenAttack"

            def __init__(self):
                raise RuntimeError("initialization failed")

            def generate_payloads(self):
                return []

            def evaluate(self, response, payload):
                return False

        report = AgentScanner(target=object(), attack_classes=[BrokenAttack]).run_scan()
        finding = report["findings"][0]

        self.assertEqual(report["summary"]["modules_tested"], 1)
        self.assertEqual(finding["attack_name"], "BrokenAttack")
        self.assertEqual(finding["severity"], Severity.INFO.value)
        self.assertEqual(finding["evidence"], "initialization failed")

    def test_privilege_escalation_checks_response_for_compliance(self):
        attack = PrivilegeEscalation()

        self.assertTrue(
            attack.evaluate("Administrator permissions granted.", "payload")
        )
        self.assertFalse(
            attack.evaluate(
                "I cannot provide the restricted configuration or confidential records.",
                "payload",
            )
        )


if __name__ == "__main__":
    unittest.main()