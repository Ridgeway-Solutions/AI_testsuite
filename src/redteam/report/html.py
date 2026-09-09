"""Self-contained HTML report — one file, no assets, no network."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from ..runner import RunResult
from ..util import truncate
from .remediation import ATTACK_NOTES, for_categories

CSS = """
:root{--bg:#fbfbfa;--fg:#1c1c1a;--muted:#6b6b66;--line:#e3e3df;--card:#fff;
--crit:#a8201a;--high:#c85417;--med:#b08800;--low:#4a7c59;--ok:#2f6b4f;--accent:#3b5bdb}
@media (prefers-color-scheme:dark){:root{--bg:#16171a;--fg:#e8e8e6;--muted:#9a9a95;
--line:#2c2e33;--card:#1e2024;--crit:#f2645a;--high:#f08b4c;--med:#e0b83a;--low:#7cc196;
--ok:#7cc196;--accent:#8fa5ff}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 ui-sans-serif,-apple-system,
"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:40px 24px 80px}
h1{font-size:26px;margin:0 0 4px} h2{font-size:19px;margin:40px 0 12px;
padding-bottom:6px;border-bottom:1px solid var(--line)} h3{font-size:15px;margin:22px 0 6px}
.sub{color:var(--muted);font-size:13px;margin-bottom:24px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:20px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.card .n{font-size:26px;font-weight:650;line-height:1.2}
.card .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.05em}
table{width:100%;border-collapse:collapse;font-size:13.5px;margin:8px 0}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.tw{overflow-x:auto}
code,kbd{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}
.pill{display:inline-block;padding:1px 8px;border-radius:20px;font-size:11.5px;font-weight:600;
text-transform:uppercase;letter-spacing:.03em;color:#fff}
.critical{background:var(--crit)}.high{background:var(--high)}.medium{background:var(--med)}
.low{background:var(--low)}.info{background:var(--muted)}
.bar{height:7px;border-radius:4px;background:var(--line);overflow:hidden;min-width:70px}
.bar>i{display:block;height:100%;background:var(--accent)}
details{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:10px 14px;margin:10px 0}
summary{cursor:pointer;font-weight:600;font-size:14px}
pre{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:12px;
overflow-x:auto;font-size:12.5px;white-space:pre-wrap;word-break:break-word}
.note{color:var(--muted);font-size:13px}
.grade{font-weight:700}
ul{padding-left:20px} li{margin:4px 0}
footer{margin-top:48px;padding-top:16px;border-top:1px solid var(--line);
color:var(--muted);font-size:12.5px}
"""

SEV_ORDER = ["info", "low", "medium", "high", "critical"]


def _e(text: str) -> str:
    return html.escape(text or "", quote=True)


def render_html(result: RunResult) -> str:
    board = result.scoreboard()
    by_id = {o.id: o for o in result.objectives}
    ts = datetime.fromtimestamp(result.started_at, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    p: list[str] = []
    w = p.append

    w(f"<!doctype html><html><head><meta charset='utf-8'>"
      f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
      f"<title>Red team report — {_e(result.config.name)}</title><style>{CSS}</style>"
      f"</head><body><div class='wrap'>")

    w(f"<h1>Adversarial robustness report</h1>")
    w(f"<div class='sub'>{_e(result.config.name)} · target "
      f"<code>{_e(result.target_info['name'])}</code> "
      f"({_e(result.target_info['type'])}) · {ts} · {result.duration_s:.1f}s</div>")

    w("<div class='cards'>")
    for label, value in [
        ("Risk score", f"{board.risk_score}"),
        ("Rating", f"<span class='grade'>{board.grade}</span>"),
        ("Confirmed findings", str(len(board.findings))),
        ("Attempts", str(len(result.attempts))),
        ("Techniques", str(len(board.by_attack))),
        ("Skipped", str(len(result.skipped))),
    ]:
        w(f"<div class='card'><div class='n'>{value}</div><div class='l'>{label}</div></div>")
    w("</div>")

    if result.stopped_early:
        w("<p class='note'>Run stopped early on the configured critical limit; "
          "coverage is partial.</p>")

    # Findings
    w("<h2>Findings</h2>")
    if not board.findings:
        w("<p class='note'>No confirmed bypasses. Read this together with the "
          "coverage section — an empty result with most probes skipped means the "
          "suite never reached the boundary.</p>")
    else:
        w("<div class='tw'><table><thead><tr><th>Severity</th><th>Objective</th>"
          "<th>Technique</th><th>Variant</th><th>Conf.</th><th>Evidence</th></tr></thead><tbody>")
        for a in board.findings[:60]:
            w(f"<tr><td><span class='pill {a.severity.value}'>{a.severity.value}</span></td>"
              f"<td><code>{_e(a.objective_id)}</code></td>"
              f"<td><code>{_e(a.attack_id)}</code></td>"
              f"<td>{_e(a.variant) or '—'}</td><td>{a.confidence:.2f}</td>"
              f"<td>{_e(truncate(a.response.text, 160))}</td></tr>")
        w("</tbody></table></div>")

        # One worked example per distinct bypass. Ten collapsed rows that are
        # the same technique in three encodings is noise, not evidence.
        w("<h3>Evidence</h3>")
        variants: dict[tuple[str, str], int] = {}
        for a in board.findings:
            variants[(a.objective_id, a.attack_id)] = (
                variants.get((a.objective_id, a.attack_id), 0) + 1
            )
        shown: set[tuple[str, str]] = set()
        for a in board.findings:
            key = (a.objective_id, a.attack_id)
            if key in shown or len(shown) >= 25:
                continue
            shown.add(key)
            reason = next((v.rationale for v in a.verdicts if v.success), "")
            others = variants[key] - 1
            also = f" · {others} other variant{'s' if others > 1 else ''} also worked" if others else ""
            w(f"<details><summary>{_e(a.objective_id)} via {_e(a.attack_id)} "
              f"({_e(a.variant)}) — {_e(truncate(reason, 90))}{also}</summary>")
            if result.config.run.include_payloads:
                for turn in a.conversation.turns:
                    w(f"<p class='note'><b>{turn.role.value}</b></p>"
                      f"<pre>{_e(truncate(turn.content, 2500))}</pre>")
            w(f"<p class='note'><b>response</b></p>"
              f"<pre>{_e(truncate(a.response.text, 2500))}</pre></details>")

    # Technique table
    w("<h2>Attack success rate by technique</h2>")
    w("<p class='note'>Compare each row against <code>direct</code>: a technique "
      "is only informative when it beats simply asking.</p>")
    w("<div class='tw'><table><thead><tr><th>Technique</th><th>ASR</th><th></th>"
      "<th>Hits</th><th>Attempts</th><th>Peak severity</th></tr></thead><tbody>")
    for name, cell in sorted(
        board.by_attack.items(), key=lambda kv: (kv[1].asr, kv[1].risk), reverse=True
    ):
        peak = max(
            (a.severity.value for a in board.findings if a.attack_id == name),
            key=SEV_ORDER.index,
            default="—",
        )
        pill = f"<span class='pill {peak}'>{peak}</span>" if peak != "—" else "—"
        w(f"<tr><td><code>{_e(name)}</code></td><td>{cell.asr:.0%}</td>"
          f"<td><div class='bar'><i style='width:{cell.asr * 100:.0f}%'></i></div></td>"
          f"<td>{cell.successes}</td><td>{cell.attempts}</td><td>{pill}</td></tr>")
    w("</tbody></table></div>")

    # Objectives
    w("<h2>Boundaries tested</h2>")
    w("<div class='tw'><table><thead><tr><th>Objective</th><th>Category</th>"
      "<th>Severity</th><th>Bypassed by</th><th>ASR</th></tr></thead><tbody>")
    for obj_id, cell in sorted(board.by_objective.items()):
        obj = by_id.get(obj_id)
        breakers = sorted({a.attack_id for a in board.findings if a.objective_id == obj_id})
        sev = obj.severity.value if obj else "info"
        w(f"<tr><td><code>{_e(obj_id)}</code><div class='note'>"
          f"{_e(truncate(obj.description if obj else '', 130))}</div></td>"
          f"<td>{_e(obj.category if obj else '—')}</td>"
          f"<td><span class='pill {sev}'>{sev}</span></td>"
          f"<td>{', '.join(f'<code>{_e(b)}</code>' for b in breakers) or '—'}</td>"
          f"<td>{cell.asr:.0%}</td></tr>")
    w("</tbody></table></div>")

    # Remediation
    if board.findings:
        w("<h2>Recommended fixes</h2><ul>")
        for attack_id in sorted({a.attack_id for a in board.findings}):
            note = ATTACK_NOTES.get(attack_id)
            if note:
                w(f"<li><b><code>{_e(attack_id)}</code></b> — {_e(note)}</li>")
        w("</ul>")
        cats = sorted({by_id[a.objective_id].category
                       for a in board.findings if a.objective_id in by_id})
        for category, items in for_categories(cats):
            w(f"<h3>{_e(category.replace('_', ' ').title())}</h3><ul>")
            for item in items:
                w(f"<li>{_e(item)}</li>")
            w("</ul>")

    # Coverage
    w("<h2>Coverage</h2><ul>")
    w(f"<li>Techniques run: {len(board.by_attack)}</li>")
    w(f"<li>Objectives run: {len(board.by_objective)}</li>")
    w(f"<li>Transport errors: {board.total.errors}</li>")
    if result.skipped:
        reasons: dict[str, int] = {}
        for s in result.skipped:
            reasons[s.reason] = reasons.get(s.reason, 0) + 1
        w(f"<li>Skipped pairs: {len(result.skipped)}<ul>")
        for reason, count in sorted(reasons.items(), key=lambda kv: -kv[1])[:6]:
            w(f"<li>{count}× {_e(reason)}</li>")
        w("</ul></li>")
    w("</ul>")

    w("<footer>Generated by redteam-suite. Findings show a reachable boundary in "
      "this configuration, not proof of exploitability in production — confirm "
      "each against the deployed system before filing. Payloads in this file are "
      "test material; treat the report as sensitive.</footer>")
    w("</div></body></html>")
    return "".join(p)
