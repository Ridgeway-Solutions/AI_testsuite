# Architecture

```
suite.yaml ──► SuiteConfig ──► Runner ──┬──► Target      (the system under test)
                                        ├──► Attack      (technique → payloads)
                                        ├──► Objective   (boundary + detectors)
                                        └──► Detector    (bypass or not?)
                                                 │
                            Attempt records ─────┴──► Scoreboard ──► reports
```

## The pieces

**`types.py`** — the data model everything crosses module boundaries as.
`Turn`/`Conversation` (what gets sent), `Response`, `Verdict`, and `Attempt`
(one attack × objective × payload, with its outcome). Attempts serialise to
JSONL, so a run can be re-scored or re-reported without re-sending anything.

**`Target`** hides the transport. Attacks never see HTTP; they build a
conversation and the target decides how to deliver it. Targets declare
`capabilities` (`multi_turn`, `assistant_prefill`, `tools`, `system_prompt`,
`seeding`) and the runner skips probes a target cannot support rather than
reporting a false pass.

**`Attack`** turns an objective into payloads. Static techniques implement
`build()`; adaptive ones override `run()` and use `ctx.send()` to look at each
response before choosing the next move — that is how `crescendo` backs off after
a refusal instead of burning its ladder.

**`Objective`** is a boundary: a goal, a severity, and the detectors that decide
whether it was crossed. `only_attacks` scopes an objective to specific
techniques (over-refusal controls use it); `requires_seed` marks objectives that
need a harness-installed system prompt.

**`Detector`** answers one question and reports a confidence with its reasoning.
Combinators (`all`, `any`) compose them. `judge_all` falls back to refusal-only
detection when an objective configures none.

**`Runner`** builds the plan (every viable attack × objective pair, plus the
skips and their reasons), then executes it with request-level concurrency, a
shared token-bucket rate limiter, and per-request retries. Results stream to
JSONL as they land.

**`scoring.py`** aggregates attempts into ASR cells by attack, objective,
category and severity, and computes a risk score weighted toward the worst
findings.

**`report/`** renders Markdown, HTML and JSON from the same scoreboard.

**`tui/`** is the terminal UI. `tui/state.py` holds every decision about what is
on screen and knows nothing about curses; `tui/app.py` owns the screen, the
keyboard and the worker thread a scan runs on. Splitting them that way is what
makes the interesting half testable without a terminal.

## Decisions worth knowing about

**Concurrency is bounded per request, not per pair.** Pairs run concurrently and
each issues its requests through a shared semaphore, so one long adaptive attack
cannot monopolise the budget.

**Targets return errors, they do not raise.** A transport failure becomes a
`Response` with `error` set, so a flaky endpoint degrades into errored attempts
that are excluded from ASR denominators rather than aborting the run.

**One broken plugin cannot kill a run.** Exceptions from an attack are caught,
reported as an `attack_error` event, and the rest of the plan continues.

**Confidence is first-class.** Detectors report how sure they are and the
scoreboard holds hits below `CONFIDENCE_FLOOR` out of the findings list. The
refusal detector caps itself at 0.6 because "did not refuse" is weak evidence.

**The UI never touches the runner's data structures.** A scan is asyncio and a
screen is a blocking read loop, so the run owns a worker thread and reports
through a queue that the draw loop drains between frames. The views are built
from the serialised event payloads rather than from the live `RunResult`:
iterating a list another thread is appending to is a race, and the payloads
already carry everything a view needs. The only call in the other direction is
`Runner.request_stop`, through `loop.call_soon_threadsafe`.

**An in-progress boundary is never drawn as a pass.** Mid-run the boundaries
view shows live tallies and no verdict at all. `PASS`/`FAIL` appear only once
the run has finished and `objective_outcomes` has spoken, for the same reason
the reports distinguish `NOT RUN` from `PASS`: a boundary nothing has reached
*yet* is not a boundary that held.

**No required HTTP dependency.** Requests go through `urllib` in a worker
thread. It keeps the install trivial and avoids version conflicts with the
application you are testing when the suite is vendored into its repo.

## Adding to it

See [EXTENDING.md](EXTENDING.md). Everything registers by decorator
(`@register_attack`, `@register_target`, `@register_detector`) and is discovered
by importing the subpackage, so a new technique is one file and no wiring.
