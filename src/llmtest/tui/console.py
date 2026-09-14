"""The `:` command line inside the UI.

The suite ships pointed at an offline mock, which proves the machinery works
and tests nothing of yours. This is where you point it at something real —
any endpoint, any model, any local command — without leaving the UI or
writing YAML first::

    :target https://my-app.internal/api/chat
    :response-path data.reply
    :auth APP_TOKEN
    :test
    :run

curses-free, like ``state`` and ``target_form``: parsing a line and deciding
what it means is the part worth testing, and none of it needs a terminal. The
app supplies a *host* (itself) exposing the few verbs a command can perform.

Anything typed here is treated as the user's own instruction — but a target is
still refused unless it is http/https, because "point it at anything" must not
mean "point it at a file:// URL and read the disk".
"""

from __future__ import annotations

import shlex
from collections import deque
from dataclasses import dataclass
from typing import Any, Callable

from .state import KIND_ERROR, KIND_HELD, KIND_MUTED, KIND_PLAIN, KIND_WARN
from .target_form import FIELDS, KINDS, TargetForm, new_canary

MAX_OUTPUT = 500
MAX_HISTORY = 100


@dataclass
class Line:
    text: str
    kind: str = KIND_PLAIN


@dataclass(frozen=True)
class Command:
    name: str
    usage: str
    help: str
    handler: Callable[["Console", list[str]], None]
    aliases: tuple[str, ...] = ()


class Console:
    """The prompt, its scrollback, and the commands it understands."""

    def __init__(self, host: Any) -> None:
        self.host = host
        self.open = False
        self.buffer = ""
        self.cursor = 0
        self.output: deque[Line] = deque(maxlen=MAX_OUTPUT)
        self.history: list[str] = []
        self.history_pos: int | None = None

    # -- the prompt -----------------------------------------------------------

    def begin(self, seed: str = "") -> None:
        self.open = True
        self.buffer = seed
        self.cursor = len(seed)
        self.history_pos = None

    def close(self) -> None:
        self.open = False
        self.buffer = ""
        self.cursor = 0
        self.history_pos = None

    def type_char(self, char: str) -> None:
        if not char.isprintable():
            return
        self.buffer = self.buffer[:self.cursor] + char + self.buffer[self.cursor:]
        self.cursor += 1

    def backspace(self) -> None:
        if self.cursor:
            self.buffer = self.buffer[:self.cursor - 1] + self.buffer[self.cursor:]
            self.cursor -= 1
        elif not self.buffer:
            # Backspacing past the start of an empty line closes the prompt, the
            # way deleting the ':' does in an editor.
            self.close()

    def move_cursor(self, delta: int) -> None:
        self.cursor = max(0, min(len(self.buffer), self.cursor + delta))

    def recall(self, delta: int) -> None:
        """Walk the history: -1 is older, +1 newer."""
        if not self.history:
            return
        if self.history_pos is None:
            self.history_pos = len(self.history)
        self.history_pos = max(0, min(len(self.history), self.history_pos + delta))
        self.buffer = "" if self.history_pos == len(self.history) \
            else self.history[self.history_pos]
        self.cursor = len(self.buffer)

    def submit(self) -> None:
        line = self.buffer.strip()
        self.close()
        if not line:
            return
        if not self.history or self.history[-1] != line:
            self.history.append(line)
            del self.history[:-MAX_HISTORY]
        self.echo(f":{line}", KIND_MUTED)
        self.execute(line)

    # -- output ---------------------------------------------------------------

    def echo(self, text: str, kind: str = KIND_PLAIN) -> None:
        self.output.append(Line(text, kind))

    def ok(self, text: str) -> None:
        self.echo(text, KIND_HELD)

    def warn(self, text: str) -> None:
        self.echo(text, KIND_WARN)

    def error(self, text: str) -> None:
        self.echo(text, KIND_ERROR)

    @property
    def last(self) -> str:
        return self.output[-1].text if self.output else ""

    # -- dispatch -------------------------------------------------------------

    def execute(self, line: str) -> None:
        try:
            parts = shlex.split(line)
        except ValueError as exc:  # an unbalanced quote
            self.error(f"could not parse that: {exc}")
            return
        if not parts:
            return
        name, args = parts[0].lstrip(":").lower(), parts[1:]
        command = lookup(name)
        if command is None:
            self.error(f"unknown command: {name}  (try :help)")
            return
        try:
            command.handler(self, args)
        except CommandError as exc:
            self.error(str(exc))
        except Exception as exc:  # noqa: BLE001 — a typo must not kill the UI
            self.error(f"{name} failed: {exc!r}")


class CommandError(Exception):
    """A command the user got wrong. Reported, never fatal."""


# --------------------------------------------------------------------------- verbs


def _form(console: Console) -> TargetForm:
    return console.host.form


def _spec_of(form: TargetForm, key: str) -> Any:
    for spec in FIELDS[form.kind]:
        if spec.key == key:
            return spec
    raise CommandError(f"a {form.kind} target has no {key}")


def _need(args: list[str], usage: str) -> None:
    if not args:
        raise CommandError(f"usage: {usage}")


def _applied(console: Console) -> None:
    """Re-cost the run after the target changed, and say what it now aims at."""
    message = console.host.apply_target()
    if message:
        console.error(message)
        return
    console.ok(f"target: {_form(console).describe()}")
    for problem in _form(console).problems():
        console.warn(f"  {problem}")


def cmd_target(console: Console, args: list[str]) -> None:
    form = _form(console)
    if not args:
        cmd_show(console, [])
        return

    first = args[0]
    if first.startswith(("http://", "https://")):
        form.switch("http")
        form.set("url", first)
    elif first in KINDS:
        form.switch(first)
        rest = " ".join(args[1:])
        if rest:
            if first == "shell":
                form.set("command", rest)
            elif first == "mock":
                form.set("profile", rest)
            elif first == "http":
                form.set("url", rest)
            else:
                form.set("model", rest)
    elif "://" in first:
        raise CommandError(
            f"{first.split('://')[0]}:// targets are not allowed - "
            f"this sends attack payloads, so it only speaks http and https"
        )
    else:
        raise CommandError(
            "usage: :target <url> | :target " + " | :target ".join(KINDS)
        )
    _applied(console)


def cmd_model(console: Console, args: list[str]) -> None:
    _need(args, ":model <id>")
    if not _form(console).set("model", args[0]):
        raise CommandError(f"a {_form(console).kind} target has no model")
    _applied(console)


def cmd_auth(console: Console, args: list[str]) -> None:
    _need(args, ":auth <ENV_VAR>   (the variable name, never the key itself)")
    name = args[0]
    if name.count(" ") or len(name) > 64 or name.lower().startswith(("sk-", "bearer")):
        raise CommandError(
            "that looks like a key, not a variable name. Set it in your shell "
            "first, then name the variable here - a key typed at a prompt ends "
            "up in scrollback."
        )
    form = _form(console)
    key = "auth_env" if form.kind == "http" else "api_key_env"
    if not form.set(key, name):
        raise CommandError(f"a {form.kind} target takes no credentials")
    _applied(console)


def cmd_header(console: Console, args: list[str]) -> None:
    if len(args) < 2:
        raise CommandError(':header <name> <value>   e.g. :header x-api-key "${APP_KEY}"')
    form = _form(console)
    if form.kind != "http":
        raise CommandError("headers only apply to an http target")
    headers = dict(form.extra.get("headers") or {})
    headers[args[0].rstrip(":")] = " ".join(args[1:])
    form.extra["headers"] = headers
    _applied(console)


def cmd_response_path(console: Console, args: list[str]) -> None:
    _need(args, ":response-path <path>   e.g. data.reply or choices.0.message.content")
    if not _form(console).set("response_path", args[0]):
        raise CommandError(f"a {_form(console).kind} target has no response path")
    _applied(console)


def cmd_field(console: Console, args: list[str]) -> None:
    _need(args, ":field <name>   the JSON key carrying the prompt, or 'messages'")
    if not _form(console).set("prompt_field", args[0]):
        raise CommandError("only an http target has a request field")
    _applied(console)


def cmd_system(console: Console, args: list[str]) -> None:
    form = _form(console)
    text = " ".join(args)
    if not form.set("system_prompt", text):
        raise CommandError(f"a {form.kind} target carries no system prompt")

    if not text:
        form.values.pop(f"{form.kind}.canary", None)
        _applied(console)
        return

    # Plant a secret we know. "Does it leak its instructions?" can only be
    # judged against something the harness put there - your real secrets are
    # yours, and we must not ask you to type one in to find out.
    canary = form.values.get(f"{form.kind}.canary") or new_canary()
    form.values[f"{form.kind}.canary"] = canary
    console.echo(f"planted {canary} in the system prompt - a leak of it is a "
                 f"confirmed finding", KIND_MUTED)

    if form.kind == "http" and form.value_of(_spec_of(form, "prompt_field")) != "messages":
        console.warn(
            "the request field is not 'messages', so only the latest prompt "
            "reaches your endpoint and the system prompt never arrives - "
            "use :field messages if it takes a chat array"
        )
    _applied(console)


def cmd_set(console: Console, args: list[str]) -> None:
    if len(args) < 2:
        raise CommandError(":set <key> <value>   any target option, for the ones with no verb")
    form = _form(console)
    key, value = args[0], " ".join(args[1:])
    if not form.set(key, value):
        form.extra[key] = value
    _applied(console)


def cmd_show(console: Console, args: list[str]) -> None:
    form = _form(console)
    console.echo(f"target: {form.describe()}", KIND_HELD)
    for spec, value, note in form.rows():
        shown = value or "-"
        suffix = f"   ({note})" if note else ""
        console.echo(f"  {spec.label:<16}{shown}{suffix}",
                     KIND_WARN if note == "NOT SET in this shell" else KIND_PLAIN)
    config = console.host.config
    console.echo(f"  {'attacks':<16}{', '.join(config.attacks)}")
    console.echo(f"  {'output':<16}{console.host.outdir}")
    for problem in form.problems():
        console.warn(f"  {problem}")


def cmd_attacks(console: Console, args: list[str]) -> None:
    _need(args, ":attacks all | :attacks direct,persona,obfuscation")
    chosen = [a.strip() for a in " ".join(args).replace(",", " ").split() if a.strip()]
    console.host.config.attacks = chosen
    _applied(console)


def cmd_objectives(console: Console, args: list[str]) -> None:
    _need(args, ":objectives <file.yaml>")
    console.host.config.objectives_file = args[0]
    console.host.config.source = None
    _applied(console)


def cmd_category(console: Console, args: list[str]) -> None:
    _need(args, ":category confidentiality,policy_adherence")
    console.host.config.categories = [
        c.strip() for c in " ".join(args).replace(",", " ").split() if c.strip()
    ]
    _applied(console)


def cmd_only(console: Console, args: list[str]) -> None:
    console.host.config.include_objectives = [
        o.strip() for o in " ".join(args).replace(",", " ").split() if o.strip()
    ]
    _applied(console)


def _number(args: list[str], usage: str, cast: Callable[[str], Any]) -> Any:
    _need(args, usage)
    try:
        return cast(args[0])
    except ValueError:
        raise CommandError(f"usage: {usage}") from None


def cmd_concurrency(console: Console, args: list[str]) -> None:
    value = _number(args, ":concurrency <n>", int)
    if value < 1:
        raise CommandError("concurrency must be at least 1")
    console.host.config.run.concurrency = value
    console.ok(f"concurrency {value}")


def cmd_rate(console: Console, args: list[str]) -> None:
    value = _number(args, ":rate <requests per second, 0 = unlimited>", float)
    if value < 0:
        raise CommandError("a rate cannot be negative")
    console.host.config.run.rate_limit_rps = value
    console.ok("rate limit off" if value == 0 else f"rate limit {value}/s")


def cmd_max_turns(console: Console, args: list[str]) -> None:
    value = _number(args, ":max-turns <n>", int)
    if value < 1:
        raise CommandError("max-turns must be at least 1")
    console.host.config.run.max_turns = value
    console.ok(f"max turns {value}")


def cmd_out(console: Console, args: list[str]) -> None:
    _need(args, ":out <directory>")
    console.ok(f"reports will be written to {console.host.set_outdir(args[0])}")


def cmd_load(console: Console, args: list[str]) -> None:
    _need(args, ":load <suite.yaml>")
    message = console.host.load_suite(args[0])
    if message:
        raise CommandError(message)
    console.ok(f"loaded {args[0]}")
    cmd_show(console, [])


def cmd_save_suite(console: Console, args: list[str]) -> None:
    _need(args, ":save-suite <file.yaml>")
    path = console.host.save_suite(args[0])
    console.ok(f"wrote {path} - re-run it any time with: llmtest run {path}")


def cmd_test(console: Console, args: list[str]) -> None:
    form = _form(console)
    if not form.ready:
        raise CommandError("; ".join(form.problems()) or "the target is incomplete")
    console.echo("sending one benign request…", KIND_MUTED)
    console.host.test_connection()


def cmd_plan(console: Console, args: list[str]) -> None:
    for line in console.host.plan_lines():
        console.echo(line)


def cmd_run(console: Console, args: list[str]) -> None:
    form = _form(console)
    if not form.ready:
        raise CommandError("; ".join(form.problems()) or "the target is incomplete")
    # Running an empty plan would finish instantly and report a clean bill of
    # health for a system that was never sent anything. Refuse, and show what
    # got skipped so the next command is the one that fixes it.
    if not console.host.state.total_pairs:
        console.error("nothing to run — every pair was skipped:")
        for line in console.host.plan_lines()[2:]:
            console.echo(f"  {line}", KIND_WARN)
        console.echo("  widen it with :attacks all, clear :only / :category, "
                     "or give the target what the objectives need", KIND_MUTED)
        return
    message = console.host.start_run()
    if message:
        raise CommandError(message)
    console.ok(f"running against {form.describe()}")


def cmd_stop(console: Console, args: list[str]) -> None:
    console.host.stop_run()


def cmd_save(console: Console, args: list[str]) -> None:
    console.echo(console.host.save_reports())


def cmd_quit(console: Console, args: list[str]) -> None:
    console.host.quit()


def cmd_help(console: Console, args: list[str]) -> None:
    if args:
        command = lookup(args[0].lstrip(":").lower())
        if command is None:
            raise CommandError(f"no such command: {args[0]}")
        console.echo(f"{command.usage}", KIND_HELD)
        console.echo(f"  {command.help}")
        if command.aliases:
            console.echo(f"  also: {', '.join(':' + a for a in command.aliases)}")
        return
    console.echo("commands — :help <name> for one of them", KIND_HELD)
    for command in COMMANDS:
        console.echo(f"  {command.usage:<34}{command.help}")


COMMANDS: tuple[Command, ...] = (
    Command("target", ":target <url> | <type> [model]",
            "point the run at an endpoint, a provider, a command, or the mock",
            cmd_target, ("t",)),
    Command("model", ":model <id>", "model id for an API target", cmd_model),
    Command("auth", ":auth <ENV_VAR>",
            "name the environment variable holding the key or token", cmd_auth),
    Command("header", ":header <name> <value>",
            "an extra request header, e.g. x-api-key ${APP_KEY}", cmd_header),
    Command("response-path", ":response-path <path>",
            "where the reply sits in the JSON your endpoint returns",
            cmd_response_path, ("rp",)),
    Command("field", ":field <name>",
            "the JSON key carrying the prompt, or 'messages' for a chat array",
            cmd_field),
    Command("system", ":system <text>",
            "system prompt to send with every request (API targets)", cmd_system),
    Command("set", ":set <key> <value>", "any other target option, verbatim", cmd_set),
    Command("show", ":show", "what the run is currently aimed at", cmd_show),
    Command("attacks", ":attacks <all|a,b,c>", "which techniques to run", cmd_attacks),
    Command("objectives", ":objectives <file>",
            "objectives written for your own application", cmd_objectives),
    Command("category", ":category <a,b>", "limit to objective categories", cmd_category),
    Command("only", ":only <ids>", "limit to named objectives", cmd_only),
    Command("concurrency", ":concurrency <n>", "requests in flight at once", cmd_concurrency),
    Command("rate", ":rate <rps>", "cap requests per second (0 = unlimited)", cmd_rate),
    Command("max-turns", ":max-turns <n>", "turn budget for multi-turn attacks",
            cmd_max_turns),
    Command("out", ":out <dir>", "where reports are written", cmd_out),
    Command("load", ":load <suite.yaml>", "open an existing suite file", cmd_load),
    Command("save-suite", ":save-suite <file>",
            "write the current setup out as a re-runnable suite", cmd_save_suite),
    Command("test", ":test", "send one benign request and show what came back", cmd_test),
    Command("plan", ":plan", "what would run, without sending anything", cmd_plan),
    Command("run", ":run", "start the scan", cmd_run, ("r",)),
    Command("stop", ":stop", "wind the run down after the payloads in flight", cmd_stop),
    Command("save", ":save", "write reports for the finished run", cmd_save),
    Command("help", ":help [command]", "this list", cmd_help, ("h", "?")),
    Command("quit", ":quit", "leave", cmd_quit, ("q", "exit")),
)

_BY_NAME: dict[str, Command] = {}
for _command in COMMANDS:
    _BY_NAME[_command.name] = _command
    for _alias in _command.aliases:
        _BY_NAME[_alias] = _command


def lookup(name: str) -> Command | None:
    return _BY_NAME.get(name)
