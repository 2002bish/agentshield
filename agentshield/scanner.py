# agentshield/scanner.py
#
# Production-Grade Scanner Orchestrator for AgentShield
# Automatically discovers and executes all registered attack modules against a target agent.

import logging
import time
from datetime import datetime
from typing import Any, Dict, List, Type

from agentshield.attacks.base import BaseAttack, Finding, Severity

# Import all 7 production-grade attack modules
from agentshield.attacks.prompt_injection import DirectPromptInjection
from agentshield.attacks.indirect_prompt import IndirectPromptInjection
from agentshield.attacks.tool_hijacking import ToolHijacking
from agentshield.attacks.privilege_escalation import PrivilegeEscalation
from agentshield.attacks.memory_poisoning import MemoryPoisoning
from agentshield.attacks.toctou import TOCTOUAttack
from agentshield.attacks.multi_agent import MultiAgentCompromise

# Configure module-level logger
logger = logging.getLogger("agentshield.scanner")


class AgentScanner:
    """
    Core orchestrator that runs comprehensive security audits across 
    all registered attack categories.
    """

    def __init__(self, target: Any, attack_classes: List[Type[BaseAttack]] = None):
        """
        Args:
            target: The agent wrapper object that implements a query(payload) method.
            attack_classes: Optional custom list of attack classes. If None, 
                            defaults to the full suite of AgentShield attack modules.
        """
        self.target = target
        
        # Register all core attack vectors
        self.attack_classes = attack_classes or [
            DirectPromptInjection,
            IndirectPromptInjection,
            ToolHijacking,
            PrivilegeEscalation,
            MemoryPoisoning,
            TOCTOUAttack,
            MultiAgentCompromise,
        ]

    def run_scan(self) -> Dict[str, Any]:
        """
        Executes all registered attack modules against the target, aggregates 
        findings, calculates safety ratings, and produces a structured JSON report.
        """
        logger.info(f"Starting AgentShield security scan. Total attack modules queued: {len(self.attack_classes)}")
        start_time = time.time()
        
        findings: List[Finding] = []

        for attack_cls in self.attack_classes:
            attack_instance = attack_cls()
            logger.info(f"Executing module: {attack_instance.name} (OWASP: {attack_instance.owasp_id})")
            
            try:
                # Production guard: Run attack module with individual error containment
                finding = attack_instance.run(self.target)
                findings.append(finding)
            except Exception as e:
                logger.error(f"Attack module '{attack_cls.__name__}' encountered a fatal error: {str(e)}")
                # Append a fallback informational finding so the report template remains intact
                findings.append(
                    Finding(
                        attack_name=getattr(attack_cls, "name", attack_cls.__name__),
                        severity=Severity.INFO,
                        score=0.0,
                        description="Attack module execution failed due to an unexpected exception.",
                        evidence=str(e),
                        agent_response="N/A",
                        owasp_id=getattr(attack_cls, "owasp_id", "UNKNOWN"),
                        cwe_id=getattr(attack_cls, "cwe_id", "UNKNOWN"),
                        fix="Inspect scanner logs to resolve internal module exceptions."
                    )
                )

        duration = round(time.time() - start_time, 2)
        report = self._generate_report(findings, duration)
        
        logger.info(
            f"Scan finished in {duration}s. "
            f"Modules flagged vulnerable: {report['summary']['vulnerable_modules_count']}/{len(findings)}"
        )
        return report

    def _generate_report(self, findings: List[Finding], duration: float) -> Dict[str, Any]:
        """Aggregates individual findings into an enterprise-ready summary report dictionary."""
        total_score = sum(f.score for f in findings)
        max_possible_score = len(findings) * 10.0
        
        # Calculate overall safety score percentage (100% = completely secure, 0% = completely compromised)
        overall_safety_score = (
            round((1.0 - (total_score / max_possible_score)) * 100, 2) 
            if max_possible_score > 0 else 100.0
        )

        severity_counts = {
            Severity.CRITICAL.value: sum(1 for f in findings if f.severity == Severity.CRITICAL),
            Severity.HIGH.value:     sum(1 for f in findings if f.severity == Severity.HIGH),
            Severity.MEDIUM.value:   sum(1 for f in findings if f.severity == Severity.MEDIUM),
            Severity.LOW.value:      sum(1 for f in findings if f.severity == Severity.LOW),
            Severity.INFO.value:     sum(1 for f in findings if f.severity == Severity.INFO),
        }

        vulnerable_count = sum(1 for f in findings if f.is_vulnerable())

        return {
            "metadata": {
                "scanner": "AgentShield",
                "version": "1.0.0",
                "timestamp": datetime.now().isoformat(),
                "scan_duration_seconds": duration,
            },
            "summary": {
                "overall_safety_score_percentage": overall_safety_score,
                "modules_tested": len(findings),
                "vulnerable_modules_count": vulnerable_count,
                "severity_breakdown": severity_counts,
            },
            "findings": [f.to_dict() for f in findings],
        }