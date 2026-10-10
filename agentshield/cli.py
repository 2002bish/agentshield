import argparse
import importlib
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

from agentshield.scanner import AgentScanner
from agentshield.targets.http_target import OpenAICompatibleTarget
from agentshield.report.formatters import render_html_report


def _load_python_target(specification: str) -> Any:
    module_name, separator, attribute_path = specification.partition(":")
    if not separator or not module_name or not attribute_path:
        raise ValueError("Python targets must use the form module:factory.")
    value: Any = importlib.import_module(module_name)
    for name in attribute_path.split("."):
        value = getattr(value, name)
    target = value() if callable(value) else value
    if not callable(getattr(target, "query", None)):
        raise TypeError("Python target must provide a callable query(payload) method.")
    return target


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentshield",
        description="Run a prompt-based security scan against an AI agent.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="Run a scan and export its report.")
    target_group = scan.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--url", help="OpenAI-compatible chat-completions URL.")
    target_group.add_argument(
        "--python-target",
        help="Local Python target factory, in module:callable form. Never sent to the service.",
    )
    scan.add_argument("--model", help="Model name required with --url.")
    scan.add_argument(
        "--api-key",
        default=os.environ.get("AGENTSHIELD_TARGET_API_KEY"),
        help="Target API key; defaults to AGENTSHIELD_TARGET_API_KEY.",
    )
    scan.add_argument("--output", type=Path, help="Write a report to this path.")
    scan.add_argument("--format", choices=("json", "html"), default="json")
    scan.add_argument(
        "--confirm-authorized",
        action="store_true",
        help="Confirm that you own or are authorized to test the target agent.",
    )
    return parser


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    args = _parser().parse_args()
    try:
        if not args.confirm_authorized:
            raise ValueError(
                "Pass --confirm-authorized only if you own or are authorized to test this agent."
            )
        if args.url:
            if not args.model:
                raise ValueError("--model is required with --url.")
            if not args.api_key:
                raise ValueError("Set --api-key or AGENTSHIELD_TARGET_API_KEY.")
            target = OpenAICompatibleTarget(args.url, args.api_key, args.model)
        else:
            target = _load_python_target(args.python_target)

        report = AgentScanner(target=target).run_scan()
        output = (
            render_html_report(report)
            if args.format == "html"
            else json.dumps(report, indent=2, ensure_ascii=False)
        )
        if args.output:
            args.output.write_text(output, encoding="utf-8")
        else:
            sys.stdout.write(output + ("" if output.endswith("\n") else "\n"))
    except Exception as exc:
        logging.getLogger("agentshield.cli").error("%s", exc)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()