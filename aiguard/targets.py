"""How AI Guard talks to the app under test."""
import importlib
import json
import os
import re
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional

from .scenario import Action, Response, Scenario


class Target:
    name = "target"
    reports_actions = False

    def send(self, scenario: Scenario) -> Response:  # pragma: no cover - interface
        raise NotImplementedError


def _dig(data: Any, path: str) -> Any:
    """Follow a dotted path like 'choices.0.message.content'."""
    cur = data
    for part in path.split(".") if path else []:
        if isinstance(cur, list):
            cur = cur[int(part)]
        elif isinstance(cur, dict):
            cur = cur[part]
        else:
            raise KeyError(part)
    return cur


_ENV = re.compile(r"\$\{([A-Z0-9_]+)\}")


def _expand_env(value: str) -> str:
    def repl(m):
        if m.group(1) not in os.environ:
            raise ValueError("environment variable %s is not set" % m.group(1))
        return os.environ[m.group(1)]
    return _ENV.sub(repl, value)


def _fill(template: Any, message: str) -> Any:
    """Replace the {{message}} placeholder anywhere inside a JSON template."""
    if isinstance(template, str):
        return template.replace("{{message}}", message)
    if isinstance(template, list):
        return [_fill(t, message) for t in template]
    if isinstance(template, dict):
        return {k: _fill(v, message) for k, v in template.items()}
    return template


def _parse_actions(raw: Any) -> List[Action]:
    out = []
    for item in raw or []:
        if isinstance(item, str):
            out.append(Action(item))
        elif isinstance(item, dict) and "name" in item:
            out.append(Action(str(item["name"]), bool(item.get("confirmed", False)),
                              {str(k): str(v) for k, v in (item.get("args") or {}).items()}))
    return out


class HttpTarget(Target):
    """Any chat endpoint that accepts JSON. Configured in a JSON file:

    {
      "url": "https://staging.example.com/api/chat",
      "headers": {"Authorization": "Bearer ${TEST_TOKEN}"},
      "body": {"message": "{{message}}"},
      "response_path": "reply",
      "actions_path": "actions"        (optional)
    }
    """

    def __init__(self, cfg: Dict[str, Any], timeout: float = 30.0):
        if not cfg.get("url"):
            raise ValueError("target config needs a 'url'")
        if not str(cfg["url"]).startswith(("http://", "https://")):
            raise ValueError("target url must start with http:// or https://")
        self.url = cfg["url"]
        self.headers = {k: _expand_env(str(v)) for k, v in (cfg.get("headers") or {}).items()}
        self.body = cfg.get("body", {"message": "{{message}}"})
        self.response_path = cfg.get("response_path", "reply")
        self.actions_path = cfg.get("actions_path")
        self.reports_actions = bool(self.actions_path)
        self.timeout = timeout
        self.name = self.url

    def send(self, scenario: Scenario) -> Response:
        payload = json.dumps(_fill(self.body, scenario.as_single_message())).encode()
        headers = {"Content-Type": "application/json", "User-Agent": "ai-guard/0.1"}
        headers.update(self.headers)
        req = urllib.request.Request(self.url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                data = json.loads(r.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            return Response("", error="HTTP %s from target" % e.code)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            return Response("", error="could not reach target: %s" % getattr(e, "reason", e))
        except ValueError:
            return Response("", error="target did not return JSON")
        try:
            text = str(_dig(data, self.response_path))
        except (KeyError, IndexError, ValueError, TypeError):
            return Response("", error="response_path '%s' not found in reply" % self.response_path)
        actions: List[Action] = []
        if self.actions_path:
            try:
                actions = _parse_actions(_dig(data, self.actions_path))
            except (KeyError, IndexError, ValueError, TypeError):
                actions = []
        return Response(text, actions)


class PythonTarget(Target):
    """A function in your own code: 'package.module:function'.

    The function receives a Scenario and returns a Response, a str, or a dict
    {"text": ..., "actions": [...]}. Use this to test your app in-process,
    with the real retrieval and tool code but a test configuration.
    """

    reports_actions = True

    def __init__(self, spec: str):
        if ":" not in spec:
            raise ValueError("python target must look like 'module:function'")
        mod, fn = spec.split(":", 1)
        self.fn: Callable[[Scenario], Any] = getattr(importlib.import_module(mod), fn)
        self.name = spec

    def send(self, scenario: Scenario) -> Response:
        try:
            out = self.fn(scenario)
        except Exception as e:  # report, don't crash the whole run
            return Response("", error="%s: %s" % (type(e).__name__, e))
        if isinstance(out, Response):
            return out
        if isinstance(out, dict):
            return Response(str(out.get("text", "")), _parse_actions(out.get("actions")))
        return Response(str(out))
