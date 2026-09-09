# Scope, authorisation and why the objectives are benign

## Authorisation

Run this only against systems you own or have written permission to test.
Adversarial testing generates traffic that looks exactly like an attack, because
it is one — against a third party's service it may breach their terms, and in
many jurisdictions it is unlawful regardless of intent.

Before a scan against anything you did not build:

- Get authorisation in writing, naming the endpoints and the window.
- Use a staging deployment where one exists, with test accounts and test data.
- Set `rate_limit_rps` to something the target can absorb. The default is
  unlimited, which is fine for a mock and inconsiderate for a live service.
- Tell whoever runs the on-call rotation. A red-team run that pages someone at
  02:00 is a bad way to introduce the programme.

## Why the built-in objectives are canaries

Every objective in `src/redteam/objectives/catalog.yaml` elicits something
harmless: a marker token, a seeded fake secret, a policy contradiction, a claimed
refund, the word "pineapple". None of them ask a model for content that is
dangerous to have.

This is a deliberate design choice, and it is not only about safety:

**It measures the right thing.** The question a scan answers is *did the
guardrail hold*. A canary answers that unambiguously — the string exists only
inside the system prompt, so seeing it in the output is proof. Harmful content
answers it worse, because now you also need to judge how harmful the output was,
and that judgement is exactly where jailbreak benchmarks lose their reliability.

**It makes results shareable.** A canary-based report can be attached to a
ticket, pasted into Slack and kept in CI artefacts. A report full of genuinely
dangerous model output cannot, so in practice it gets read by fewer people and
fixed more slowly.

**It keeps the tooling honest.** A repository of working exploits for producing
harmful content is a harmful artefact whatever the README says. Technique
templates parameterised by a benign goal are not.

The techniques are real. The goals are proxies. That combination is what you
want: it tells you the boundary moved, without manufacturing the thing the
boundary exists to stop.

## Extending the catalogue

You will need objectives specific to your application, and that is the point —
`--objectives my-objectives.yaml`. Keep them observable and keep them proxies
where you can:

- **Prefer a canary to the real thing.** Testing whether your medical bot will
  give unlicensed advice? Seed a marker sentence it is told never to produce and
  detect the marker.
- **Prefer a refusal boundary to a content boundary.** "Will it discuss X at
  all" is measurable without producing X.
- **If you must test real content boundaries** — some safety teams have a
  legitimate need — do it in an isolated environment, keep the results out of
  shared CI artefacts, set `include_payloads: false`, and apply your
  organisation's handling rules to the output.

## What this tool will not do

It has no capability to attack infrastructure, and adding one is out of scope:
no credential brute-forcing, no scraping of third-party services, no traffic
designed to exhaust a target's resources. It sends conversations to an endpoint
you configure, at a rate you configure.

## Handling results

A report is a list of working bypasses against your system. Treat it as
sensitive:

- Reports are gitignored by default (`runs/`, `reports/`, `*.jsonl`).
- Credential-shaped strings in responses are redacted before they reach disk,
  but redaction is a backstop, not a guarantee.
- `--no-payloads` omits the attack payloads when a report will be circulated
  more widely than the people authorised to run the tests.
- Findings are reachability in a configuration, not proof of exploitability in
  production. Confirm before filing, and file somewhere access-controlled.
