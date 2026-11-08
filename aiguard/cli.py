"""Command line entry point."""
import argparse
import json
import os
import sys
from typing import List, Optional

from . import __version__, demo
from .probes import PROBES, Context
from .report import to_console, to_html, to_json
from .runner import ORDER, run, select
from .targets import HttpTarget, PythonTarget

LEVELS = ["critical", "high", "medium", "low", "none"]


def _load_json(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        raise ValueError("file not found: %s" % path)
    except json.JSONDecodeError as e:
        raise ValueError("%s is not valid JSON: %s" % (path, e))
    if not isinstance(data, dict):
        raise ValueError("%s must contain a JSON object" % path)
    return data


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ai-guard", description="Test an LLM app for prompt injection, data leakage and unsafe actions.")
    p.add_argument("--version", action="version", version="ai-guard " + __version__)
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("list", help="list the probes")
    r = sub.add_parser("run", help="run the probes against a target")
    t = r.add_mutually_exclusive_group(required=True)
    t.add_argument("--demo", choices=["vulnerable", "guarded"], help="built-in demo chatbot (no network)")
    t.add_argument("--http", metavar="TARGET.json", help="JSON file describing a chat endpoint")
    t.add_argument("--python", metavar="MODULE:FUNC", help="function in your own code")
    r.add_argument("--config", metavar="FILE.json", help="canaries, other_user_marker, sensitive_actions")
    r.add_argument("--only", metavar="IDS", help="comma separated probe ids, e.g. AG03,AG07")
    r.add_argument("--html", metavar="FILE", help="write an HTML report")
    r.add_argument("--json", metavar="FILE", help="write a JSON report")
    r.add_argument("--fail-on", choices=LEVELS, default="high", help="exit 1 if a failure at this level or worse (default: high)")
    r.add_argument("--delay", type=float, default=1.0, help="seconds between requests to HTTP targets (default 1)")
    r.add_argument("--max-requests", type=int, default=50, help="stop after this many requests (default 50)")
    r.add_argument("--i-have-permission", action="store_true",
                   help="required for --http: confirms you own the target or have written permission to test it")
    r.add_argument("--no-color", action="store_true")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "list":
        for pr in PROBES:
            print("%s  %-8s %-18s %s" % (pr.id, pr.severity, pr.category, pr.title))
        return 0
    if args.cmd != "run":
        build_parser().print_help()
        return 2
    try:
        cfg = _load_json(args.config) if args.config else {}
        ctx = Context(canaries=[str(c) for c in cfg.get("canaries", [])],
                      other_user_marker=cfg.get("other_user_marker"),
                      **({"sensitive_actions": cfg["sensitive_actions"]} if cfg.get("sensitive_actions") else {}))
        if args.demo:
            target = PythonTarget("aiguard.demo:" + args.demo)
            target.name = "demo:%s" % args.demo
            ctx.canaries = ctx.canaries or [demo.DEMO_CANARY]
            ctx.other_user_marker = ctx.other_user_marker or demo.DEMO_OTHER_USER
            delay = 0.0
        elif args.http:
            if not args.i_have_permission:
                print("error: --http needs --i-have-permission. Only test systems you own or have written "
                      "permission to test, preferably a staging copy.", file=sys.stderr)
                return 2
            target = HttpTarget(_load_json(args.http))
            delay = max(0.0, args.delay)
        else:
            sys.path.insert(0, os.getcwd())
            target = PythonTarget(args.python)
            delay = 0.0
        probes = select(args.only.split(",") if args.only else None)
    except (ValueError, ImportError, AttributeError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    result = run(target, ctx, probes, delay=delay, max_requests=max(1, args.max_requests))
    print(to_console(result, color=not args.no_color and sys.stdout.isatty()))
    for path, render in ((args.html, to_html), (args.json, to_json)):
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(render(result))
            print("  wrote %s" % path)
    worst = result.worst_failure()
    if args.fail_on != "none" and worst and ORDER[worst] <= ORDER[args.fail_on]:
        return 1
    return 0
