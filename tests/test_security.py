"""Security regressions from the review of the initial release.

The theme is that a report is a shared artefact built from two things the
operator would not choose to publish: their own target configuration, and text
returned by a system that may be compromised.
"""

import asyncio
import json

import pytest

from llmtest.config import SuiteConfig
from llmtest.report.html import render_html
from llmtest.report.markdown import render_markdown
from llmtest.report.json_report import render_json
from llmtest.registry import load_plugins
from llmtest.runner import Runner
from llmtest.targets.base import Target, TargetError, http_post_json
from llmtest.targets.http_json import HttpJsonTarget
from llmtest.targets.openai_compat import OpenAICompatTarget
from llmtest.types import Conversation, Response, Role, Turn
from llmtest.util import redact_tree, safe_url

SECRET = "glpat-SUPERSECRETVALUE123456"


def hostile_target(text):
    class Hostile(Target):
        id = "hostile"
        capabilities = {"multi_turn"}

        async def send(self, conversation):
            return Response(text=text)

    return Hostile()


def run_against(target, objective_id="policy.forbidden_output"):
    config = SuiteConfig.from_dict({
        "name": "sec", "attacks": ["direct"],
        "objectives": {"include": [objective_id]},
    })
    return asyncio.run(Runner(config, target=target).run())


# -- target configuration must not leak into the report -----------------------


def configured_target():
    return HttpJsonTarget(
        url=f"https://api.example.com/chat?access_token={SECRET}",
        headers={"Authorization": f"Bearer {SECRET}"},
        body={"message": "{{prompt}}", "auth": {"key": SECRET}},
        extra={"nested": {"deeper": SECRET}},
        system_prompt="Internal DB password is hunter2-PROD.",
        supports_system_prompt=True,
    )


def test_describe_withholds_secrets_nested_anywhere_in_the_options():
    """The old filter was a four-key top-level denylist, which cannot
    anticipate where an operator puts a credential."""
    described = json.dumps(configured_target().describe())
    assert SECRET not in described
    assert "hunter2-PROD" not in described


def test_describe_still_says_which_options_were_set():
    described = configured_target().describe()
    assert set(described["options_withheld"]) >= {"headers", "body", "system_prompt"}
    assert described["type"] == "http"


def test_describe_shows_the_endpoint_without_its_query_string():
    described = configured_target().describe()
    assert described["options"]["url"] == "https://api.example.com/chat?[redacted]"


def test_an_allowlisted_option_is_still_redacted_if_it_quotes_a_secret():
    target = OpenAICompatTarget(model=f"model-{SECRET}")
    assert SECRET not in json.dumps(target.describe())


def test_target_configuration_does_not_reach_report_json():
    result = run_against(configured_target())
    assert SECRET not in render_json(result)


def test_safe_url_strips_userinfo_and_query():
    assert safe_url("https://u:pw@h.example.com:8443/p?k=v") == "https://h.example.com:8443/p?[redacted]"
    assert safe_url("https://h.example.com/v1") == "https://h.example.com/v1"
    assert safe_url("not a url") == "not a url"


# -- untrusted model output must not carry markup into a shared report --------

HOSTILE = ("pineapple <img src=https://attacker.tld/beacon> "
           "[click](javascript:alert(1)) | forged | row |")


def test_markdown_neutralises_html_in_untrusted_output():
    """report.md gets pasted into wikis; not every renderer sanitises."""
    md = render_markdown(run_against(hostile_target(HOSTILE)))
    assert "<img src=https" not in md
    assert "&lt;img" in md


def test_markdown_prevents_a_forged_link_from_forming():
    md = render_markdown(run_against(hostile_target(HOSTILE)))
    # The opening bracket is escaped, so no link syntax can form.
    assert "[click]" not in md
    assert "\\[click\\]" in md


def test_markdown_prevents_a_forged_table_row():
    md = render_markdown(run_against(hostile_target(HOSTILE)))
    assert "| forged |" not in md


def test_html_report_escapes_the_same_output():
    html = render_html(run_against(hostile_target(HOSTILE)))
    assert "<img src=https" not in html and "&lt;img" in html


# -- redaction must cover every field that reaches a report -------------------


def test_credentials_in_model_output_are_redacted_everywhere():
    result = run_against(hostile_target(f"pineapple key sk-abcdefghijklmnopqrstuv"))
    assert "sk-abcdefghij" not in result.attempts[0].response.text
    for render in (render_markdown, render_json, render_html):
        assert "sk-abcdefghij" not in render(result)


def test_transport_errors_are_redacted_before_they_are_recorded():
    """Error strings quote the endpoint and up to 800 bytes of the upstream
    body, which is where a gateway echoes the key it was presented."""

    class FailingTarget(Target):
        id = "failing"
        capabilities = {"multi_turn"}

        async def send(self, conversation):
            return Response(text="", error=f"HTTP 401 from gateway: api_key={SECRET}xyz")

    result = run_against(FailingTarget())
    assert SECRET not in (result.attempts[0].response.error or "")
    assert SECRET not in render_json(result)


def test_detector_rationales_and_signals_are_redacted():
    result = run_against(hostile_target("pineapple sk-abcdefghijklmnopqrstuv"), )
    blob = json.dumps([v.to_dict() for v in result.attempts[0].verdicts])
    assert "sk-abcdefghij" not in blob


def test_a_crashing_technique_cannot_write_a_secret_into_the_report():
    class Exploding:
        id, name, description = "boom", "boom", "raises"
        taxonomy, requires, multi_turn = ["t"], set(), False

        def build(self, ctx):
            return []

        async def run(self, ctx):
            raise RuntimeError(f"token={SECRET}")
            yield  # pragma: no cover

    config = SuiteConfig.from_dict({
        "name": "sec", "objectives": {"include": ["policy.forbidden_output"]}})
    result = asyncio.run(
        Runner(config, target=hostile_target("ok"), attacks=[Exploding()]).run()
    )
    assert result.errors
    assert SECRET not in render_json(result)
    assert SECRET not in render_markdown(result)


def test_redact_tree_walks_nested_structures():
    out = redact_tree({"a": ["sk-abcdefghijklmnopqrstuv"], "b": {"c": "ghp_" + "a" * 20}})
    assert "[REDACTED]" in str(out)
    assert "sk-abcdefghij" not in str(out)


# -- transport hardening ------------------------------------------------------


def test_only_http_and_https_urls_are_requested():
    """urllib's default opener also speaks file:, ftp: and data:, so a mistyped
    target would read a local file and report it as model output."""
    for url in ("file:///etc/hostname", "ftp://example.com/x", "data:text/plain,hi"):
        with pytest.raises(TargetError, match="http or https"):
            asyncio.run(http_post_json(url, {}))


def test_the_scheme_error_does_not_echo_the_query_string():
    with pytest.raises(TargetError) as exc:
        asyncio.run(http_post_json(f"file:///x?token={SECRET}", {}))
    assert SECRET not in str(exc.value)


def test_plugin_loading_does_not_shadow_the_standard_library():
    """Prepending the CWD would let any file there shadow a stdlib module for
    the rest of the process."""
    import sys

    load_plugins(["examples.custom_plugins"])
    cwd = __import__("os").getcwd()
    if cwd in sys.path:
        assert sys.path.index(cwd) > 0
