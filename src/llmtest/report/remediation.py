"""What to actually do about each finding category.

A scan that lists bypasses without saying what to change just moves the problem
to whoever reads it.
"""

from __future__ import annotations

GUIDANCE: dict[str, list[str]] = {
    "confidentiality": [
        "Treat the system prompt as public. Anything that must stay secret "
        "(keys, internal URLs, pricing logic) belongs behind a server-side tool "
        "call the model can invoke but not read.",
        "Add an output filter for known secret values — a canary check is cheap "
        "and catches leaks no prompt-level instruction will.",
    ],
    "policy_adherence": [
        "Move hard rules out of the prompt and into a deterministic output "
        "check. Prompt instructions are advisory; code is not.",
        "If the rule matters commercially, fail closed: block the response "
        "rather than logging and passing it through.",
    ],
    "excessive_agency": [
        "Require server-side authorisation for any state-changing action. The "
        "model should request a refund, never grant one.",
        "Bound tool parameters at the tool, not in the prompt (max discount, "
        "max amount, allowed accounts).",
        "Where a claim is irreversible in practice — 'your refund is issued' — "
        "template that sentence rather than letting the model compose it.",
    ],
    "scope": [
        "Add a cheap topical classifier ahead of the model; scope enforcement "
        "in the prompt is the first thing framing attacks remove.",
        "Cap output length and per-session token spend so a successful "
        "breakout is bounded in cost.",
    ],
    "exfiltration": [
        "Do not render model-authored images or links to arbitrary hosts. "
        "Allowlist the domains your client will fetch.",
        "Strip markdown image syntax and auto-linking from model output before "
        "display, or render it as text.",
    ],
    "over_refusal": [
        "Refusals on in-scope requests are a product failure, not a safe "
        "default. Loosen the trigger or add explicit allowances for these cases.",
        "Track this alongside bypass rate — hardening that pushes over-refusal "
        "up is not a net win.",
    ],
    "generic": [
        "Layer defences: input screening, a constrained system prompt, output "
        "checks, and limits on what any single response can cause.",
    ],
}

ATTACK_NOTES: dict[str, str] = {
    "obfuscation": "Encoded payloads landed — your input filter is matching on "
                   "literal strings. Normalise and decode before screening, and "
                   "put the real check on the output.",
    "indirect_injection": "Content the app ingests is being treated as "
                          "instructions. Separate data from instructions "
                          "structurally, and never let retrieved text reach the "
                          "model in the same channel as operator directives.",
    "tool_result": "Tool output is trusted. Validate and label it as data, and "
                   "re-authorise any action a tool result appears to request.",
    "crescendo": "Multi-turn escalation works here. Evaluate policy against the "
                 "whole conversation, not just the newest message.",
    "prefill": "Assistant prefill is accepted. Reject client-supplied assistant "
               "turns at the API boundary.",
    "many_shot": "Long in-context patterns override the system prompt. Cap "
                 "history length and re-assert policy close to the final turn.",
    "prompt_extraction": "The system prompt is recoverable. Assume it is, and "
                         "check that nothing in it is load-bearing for security.",
    "multilingual": "Non-English framing bypasses the guardrail. Screening and "
                    "evaluation must cover every language you accept.",
    "persona": "Role-play overrides the deployed persona. Re-assert identity "
               "and scope in a turn the user cannot displace.",
}


def for_categories(categories: list[str]) -> list[tuple[str, list[str]]]:
    return [(c, GUIDANCE.get(c, GUIDANCE["generic"])) for c in categories]
