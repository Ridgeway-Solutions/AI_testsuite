"""Command line interface.

    llmtest run suites/quick.yaml
    llmtest run --target-type openai --model gpt-4o-mini --attacks obfuscation,crescendo
    llmtest list attacks
    llmtest plan suites/full.yaml
    llmtest init my-app.yaml
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .config import SuiteConfig
from .objectives import filter_objectives, load_objectives
from .registry import available, load_plugins
from .report import write_reports
from .runner import Runner, RunResult, build_target, select_attacks, Skip
from .scoring import Outcome, objective_outcomes
from .types import Severity

SEVERITIES = ["info", "low", "medium", "high", "critical"]

BANNER = """\
Only run this against systems you own or are explicitly authorised to test.
See docs/ETHICS.md."""


# ---------------------------------------------------------------------------- run


def _progress(quiet: bool):
    state = {"n": 0, "hits": 0}

    def hook(kind: str, payload: dict[str, Any]) -> None:
        if quiet:
            return
        if kind == "run_start":
            print(
                f"→ {payload['pairs']} attack×objective pairs "
                f"({payload['attacks']} techniques, {payload['objectives']} objectives"
                + (f", {payload['skipped']} skipped" if payload["skipped"] else "")
                + ")",
                file=sys.stderr,
            )
        elif kind == "attempt":
            state["n"] += 1
            if payload["success"]:
                state["hits"] += 1
                mark = "!" if payload["severity"] in ("high", "critical") else "+"
                print(
                    f"  {mark} {payload['objective']} via {payload['attack']}"
                    f"/{payload['variant']} "
                    f"[{payload['severity']}, conf {payload['confidence']:.2f}]",
                    file=sys.stderr,
                )
            elif state["n"] % 25 == 0:
                print(f"  … {state['n']} attempts, {state['hits']} hits",
                      file=sys.stderr)
        elif kind == "warning":
            print(f"  warning: {payload['message']}: "
                  f"{', '.join(payload.get('objectives', []))}", file=sys.stderr)
        elif kind == "attack_error":
            print(f"  ✗ {payload['attack']}/{payload['objective']}: {payload['error']}",
                  file=sys.stderr)
        elif kind == "stop_early":
            print("  ! critical limit reached — stopping", file=sys.stderr)
        elif kind == "run_end":
            print(
                f"→ done: {payload['attempts']} attempts in {payload['duration_s']}s",
                file=sys.stderr,
            )

    return hook


def _config_from_args(args: argparse.Namespace) -> SuiteConfig:
    config = SuiteConfig.load(args.suite) if args.suite else SuiteConfig()
    if args.target_type and args.target_type != config.target.get("type"):
        # Switching adapter: the old block's keys belong to a different shape,
        # so keep nothing but say so rather than dropping settings silently.
        dropped = sorted(k for k in config.target if k != "type")
        if dropped and not getattr(args, "quiet", False):
            print(f"note: --target-type {args.target_type} replaces the suite's "
                  f"target block (dropping {', '.join(dropped)})", file=sys.stderr)
        config.target = {"type": args.target_type}
    for key in ("model", "base_url", "url", "profile", "system_prompt", "api_key_env"):
        value = getattr(args, key, None)
        if value:
            config.target[key] = value
    if args.attacks:
        config.attacks = [a.strip() for a in args.attacks.split(",") if a.strip()]
    if args.objectives:
        config.objectives_file = args.objectives
        config.source = None
    if args.only:
        config.include_objectives = [o.strip() for o in args.only.split(",") if o.strip()]
    if args.category:
        config.categories = [c.strip() for c in args.category.split(",") if c.strip()]
    if args.concurrency:
        config.run.concurrency = args.concurrency
    if args.rate_limit is not None:
        config.run.rate_limit_rps = args.rate_limit
    if args.max_turns:
        config.run.max_turns = args.max_turns
    if args.no_payloads:
        config.run.include_payloads = False
    return config


def _nothing_to_run(skips: list[Skip]) -> str:
    """Why a plan came out empty, and what to do about it."""
    lines = ["", "error: nothing to run — every pair was skipped, so nothing "
                 "was tested"]
    reasons: dict[str, int] = {}
    for skip in skips:
        reasons[skip.reason] = reasons.get(skip.reason, 0) + 1
    for reason, count in sorted(reasons.items(), key=lambda kv: -kv[1]):
        lines.append(f"  {count}× {reason}")
    lines.append("")
    lines.append("  Widen it with --attacks all, drop --only/--category, or give "
                 "the target")
    lines.append("  the capability the objectives need. No report was written.")
    return "\n".join(lines)


def cmd_run(args: argparse.Namespace) -> int:
    config = _config_from_args(args)
    if not args.quiet:
        print(BANNER, file=sys.stderr)

    outdir = Path(args.out)
    runner = Runner(
        config,
        on_event=_progress(args.quiet),
        stream_path=outdir / "attempts.jsonl",
    )

    # A plan that skipped everything must not be reported as a clean run. An
    # empty scan used to print "Risk score 0.0/100 (strong)" and exit 0 — an
    # all-clear for a system that was never sent a single payload, which is the
    # most dangerous thing this tool could say.
    pairs, skips = runner.plan()
    if not pairs:
        print(_nothing_to_run(skips), file=sys.stderr)
        return 2

    result: RunResult = asyncio.run(runner.run())

    formats = [f.strip() for f in args.format.split(",") if f.strip()]
    written = write_reports(result, outdir, formats)
    board = result.scoreboard()

    if not args.quiet:
        print(file=sys.stderr)
        print(f"Risk score {board.risk_score}/100 ({board.grade}) · "
              f"{len(board.findings)} confirmed finding(s) · "
              f"{len(board.unconfirmed)} low-confidence", file=sys.stderr)
        for path in written:
            print(f"  report: {path}", file=sys.stderr)

    if args.fail_on is None:
        return 0

    threshold = SEVERITIES.index(args.fail_on)
    breaching = [
        a for a in board.findings if SEVERITIES.index(a.severity.value) >= threshold
    ]
    if breaching:
        if not args.quiet:
            print(f"FAIL: {len(breaching)} finding(s) at or above {args.fail_on}",
                  file=sys.stderr)
        return 1

    # A gate that only looks at findings passes a run that tested nothing — an
    # unreachable target, a filter that matched no objectives, a crashed plugin.
    # "No findings" and "no coverage" must not produce the same exit code.
    outcomes = objective_outcomes(board, result.objectives, result.broken_objectives)
    untested = [r for r in outcomes if r.outcome in (Outcome.NOT_RUN, Outcome.INCONCLUSIVE)]
    if not args.allow_untested and (untested or result.errors or not outcomes):
        if not args.quiet:
            if not outcomes:
                print("FAIL: the run tested no boundaries at all", file=sys.stderr)
            if untested:
                print(f"FAIL: {len(untested)} boundary/boundaries were never "
                      f"exercised: {', '.join(r.objective.id for r in untested)}",
                      file=sys.stderr)
            if result.errors:
                print(f"FAIL: {len(result.errors)} technique(s) crashed, leaving "
                      "partial coverage", file=sys.stderr)
            print("       (pass --allow-untested to gate on findings alone)",
                  file=sys.stderr)
        return 1
    return 0


# ---------------------------------------------------------------------------- tui


def cmd_tui(args: argparse.Namespace) -> int:
    from .tui import launch

    config = _config_from_args(args)
    formats = [f.strip() for f in args.format.split(",") if f.strip()]
    return launch(config, Path(args.out), formats, autostart=args.run)


# --------------------------------------------------------------------------- plan


def cmd_plan(args: argparse.Namespace) -> int:
    config = _config_from_args(args)
    runner = Runner(config)
    pairs, skips = runner.plan()
    payload = {
        "suite": config.name,
        "target": runner.target.describe(),
        "attacks": sorted({a.id for a, _ in pairs}),
        "objectives": sorted({o.id for _, o in pairs}),
        "pairs": len(pairs),
        "skipped": [s.to_dict() for s in skips],
    }
    if args.json:
        print(json.dumps(payload, indent=2))
        return 0
    print(f"Suite: {config.name}")
    print(f"Target: {runner.target.name} ({runner.target.id})")
    print(f"Pairs to run: {len(pairs)}  ({len(payload['attacks'])} techniques × "
          f"{len(payload['objectives'])} objectives)")
    if skips:
        print(f"\nSkipped ({len(skips)}):")
        seen: set[str] = set()
        for s in skips:
            if s.reason not in seen:
                seen.add(s.reason)
                print(f"  - {s.reason}")
    est = len(pairs) * 4
    print(f"\nRough request estimate: ~{est} (adaptive attacks vary).")
    return 0


# --------------------------------------------------------------------------- list


def cmd_list(args: argparse.Namespace) -> int:
    load_plugins()
    if args.what == "objectives":
        objectives = filter_objectives(
            load_objectives(args.objectives), categories=
            [c.strip() for c in args.category.split(",")] if args.category else None
        )
        for obj in objectives:
            print(f"{obj.id:32} {obj.severity.value:9} {obj.category:18} {obj.goal[:60]}")
        return 0

    kind = {"attacks": "attack", "targets": "target", "detectors": "detector"}[args.what]
    for ident, cls in available(kind).items():
        if kind == "attack":
            inst = cls()
            tags = ", ".join(inst.taxonomy)
            flag = " [multi-turn]" if inst.multi_turn else ""
            print(f"{ident:22} {inst.name}{flag}")
            print(f"{'':22} {inst.description}")
            if tags:
                print(f"{'':22} refs: {tags}")
            print()
        else:
            print(f"{ident:22} {cls.__doc__.splitlines()[0] if cls.__doc__ else ''}")
    return 0


# --------------------------------------------------------------------------- init

TEMPLATE = """\
# LLM adversarial robustness suite for {name}.
#
# Only run this against a system you own or have written authorisation to test.

name: {name}
description: Adversarial robustness scan for {name}

target:
  # Swap for: openai | anthropic | http | shell | mock  (llmtest list targets)
  type: http
  url: https://staging.example.com/api/chat
  headers:
    Authorization: "Bearer ${{APP_TOKEN}}"     # from the environment, never inline
  body:
    message: "{{{{prompt}}}}"
    history: "{{{{messages}}}}"
    conversation_id: "{{{{session_id}}}}"
  response_path: data.reply

# Techniques to run. "all" is the full library; see `llmtest list attacks`.
attacks: [all]

objectives:
  # Point this at objectives written against YOUR policy. Start by copying
  # src/llmtest/objectives/catalog.yaml and editing the goals and detectors.
  file: objectives.yaml

run:
  concurrency: 4
  rate_limit_rps: 2        # stay inside the target's limits
  retries: 2
  max_turns: 6
  seed: 1337
  include_payloads: true
"""


def cmd_init(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if path.exists() and not args.force:
        print(f"{path} exists (use --force to overwrite)", file=sys.stderr)
        return 2
    path.write_text(TEMPLATE.format(name=args.name or path.stem))
    print(f"wrote {path}")
    print("next: edit the target block, then `llmtest plan " + str(path) + "`")
    print("or skip the file entirely: `llmtest tui`, then :target <your url>")
    return 0


# --------------------------------------------------------------------------- main


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="llmtest",
        description="Automated adversarial robustness testing for LLM applications.",
        epilog=BANNER,
    )
    parser.add_argument("--version", action="version", version=f"llm-testsuite {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_target_flags(p: argparse.ArgumentParser) -> None:
        p.add_argument("suite", nargs="?", help="suite YAML file")
        p.add_argument("--target-type", help="override the target type")
        p.add_argument("--model", help="model id for API targets")
        p.add_argument("--base-url", dest="base_url", help="API base URL")
        p.add_argument("--url", help="endpoint URL for the http target")
        p.add_argument("--profile", help="mock target profile: naive|strict|vulnerable")
        p.add_argument("--system-prompt", dest="system_prompt",
                       help="system prompt to seed into the target")
        p.add_argument("--api-key-env", dest="api_key_env",
                       help="environment variable holding the API key")
        p.add_argument("--attacks", help="comma-separated technique ids, or 'all'")
        p.add_argument("--objectives", help="objectives YAML file")
        p.add_argument("--only", help="comma-separated objective ids")
        p.add_argument("--category", help="comma-separated objective categories")
        p.add_argument("--concurrency", type=int)
        p.add_argument("--rate-limit", type=float, dest="rate_limit",
                       help="max requests per second (0 = unlimited)")
        p.add_argument("--max-turns", type=int, dest="max_turns")
        p.add_argument("--no-payloads", action="store_true",
                       help="omit attack payloads from reports")

    run = sub.add_parser("run", help="execute a suite against a target")
    add_target_flags(run)
    run.add_argument("--out", default="runs/latest", help="output directory")
    run.add_argument("--format", default="md,json,html", help="report formats")
    run.add_argument("--fail-on", choices=SEVERITIES,
                     help="exit 1 when a finding at or above this severity is "
                          "confirmed, or when the run left boundaries untested")
    run.add_argument("--allow-untested", action="store_true",
                     help="with --fail-on, gate on findings alone and tolerate "
                          "skipped, errored or crashed coverage")
    run.add_argument("--quiet", action="store_true")
    run.set_defaults(func=cmd_run)

    tui = sub.add_parser(
        "tui",
        help="drive a run from a full-screen terminal UI; press : inside it to "
             "point the scan at your own endpoint (no suite file needed)",
    )
    add_target_flags(tui)
    tui.add_argument("--out", default="runs/latest", help="output directory")
    tui.add_argument("--format", default="md,json,html", help="report formats")
    tui.add_argument("--run", action="store_true",
                     help="start the scan immediately instead of on the setup screen")
    tui.set_defaults(func=cmd_tui, quiet=True)

    plan = sub.add_parser("plan", help="show what would run, without sending anything")
    add_target_flags(plan)
    plan.add_argument("--json", action="store_true")
    plan.set_defaults(func=cmd_plan)

    lst = sub.add_parser("list", help="list registered plugins or objectives")
    lst.add_argument("what", choices=["attacks", "targets", "detectors", "objectives"])
    lst.add_argument("--objectives", help="objectives YAML file")
    lst.add_argument("--category")
    lst.set_defaults(func=cmd_list)

    init = sub.add_parser("init", help="scaffold a suite file for your application")
    init.add_argument("path", nargs="?", default="llmtest.yaml")
    init.add_argument("--name")
    init.add_argument("--force", action="store_true")
    init.set_defaults(func=cmd_init)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except ImportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (KeyError, ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
