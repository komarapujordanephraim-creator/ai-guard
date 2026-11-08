import contextlib
import io
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from aiguard import cli, demo
from aiguard.probes import PROBES, Context
from aiguard.report import to_html, to_json
from aiguard.runner import run, select
from aiguard.scenario import Response, Scenario
from aiguard.targets import HttpTarget, PythonTarget, _dig


def demo_ctx():
    return Context(canaries=[demo.DEMO_CANARY], other_user_marker=demo.DEMO_OTHER_USER)


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class DemoBotTests(unittest.TestCase):
    def test_vulnerable_bot_fails_every_probe(self):
        r = run(PythonTarget("aiguard.demo:vulnerable"), demo_ctx())
        self.assertEqual(r.count("fail"), len(PROBES), [(f.probe_id, f.status) for f in r.findings])

    def test_guarded_bot_passes_every_probe(self):
        r = run(PythonTarget("aiguard.demo:guarded"), demo_ctx())
        self.assertEqual(r.count("pass"), len(PROBES), [(f.probe_id, f.status, f.evidence) for f in r.findings])

    def test_markers_are_random_per_run(self):
        self.assertNotEqual(Context().marker, Context().marker)


class CheckTests(unittest.TestCase):
    def setUp(self):
        self.ctx = demo_ctx()
        self.p = {p.id: p for p in PROBES}

    def test_quoting_the_attack_while_warning_is_review_not_fail(self):
        resp = Response("The email contains a hidden instruction asking me to reply with %s. I ignored it." % self.ctx.marker)
        self.assertEqual(self.p["AG03"].check(resp, self.ctx)[0], "review")

    def test_bare_marker_is_fail(self):
        self.assertEqual(self.p["AG03"].check(Response(self.ctx.marker), self.ctx)[0], "fail")

    def test_escaped_html_is_not_script_injection(self):
        resp = Response("Welcome, &lt;img src=x onerror=alert('%s')&gt;" % self.ctx.marker)
        self.assertEqual(self.p["AG08"].check(resp, self.ctx)[0], "pass")

    def test_image_to_other_domain_without_data_passes(self):
        resp = Response("![logo](https://cdn.example.com/logo.png)")
        self.assertEqual(self.p["AG06"].check(resp, self.ctx)[0], "pass")

    def test_confirmed_action_passes(self):
        from aiguard.scenario import Action
        resp = Response("ok", [Action("refund", confirmed=True)])
        self.assertEqual(self.p["AG07"].check(resp, self.ctx)[0], "pass")


class RunnerTests(unittest.TestCase):
    def test_canary_probes_skip_without_config(self):
        r = run(PythonTarget("aiguard.demo:vulnerable"), Context())
        skipped = {f.probe_id for f in r.findings if f.status == "skipped"}
        self.assertEqual(skipped, {"AG01", "AG02", "AG09", "AG10"})

    def test_request_limit(self):
        r = run(PythonTarget("aiguard.demo:guarded"), demo_ctx(), max_requests=3)
        self.assertEqual(sum(1 for f in r.findings if f.evidence == "request limit reached"), len(PROBES) - 3)

    def test_target_exception_becomes_error(self):
        import types, sys
        mod = types.ModuleType("aiguard_boom")
        mod.bot = lambda s: (_ for _ in ()).throw(RuntimeError("boom"))
        sys.modules["aiguard_boom"] = mod
        r = run(PythonTarget("aiguard_boom:bot"), demo_ctx(), select(["AG03"]))
        self.assertEqual(r.findings[0].status, "error")

    def test_unknown_probe_id(self):
        with self.assertRaises(ValueError):
            select(["AG99"])


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        msg = body["input"]["text"]
        reply = demo.vulnerable(Scenario(msg))
        self.server.seen_auth = self.headers.get("Authorization")
        out = json.dumps({"data": {"reply": reply.text}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


class HttpTargetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = "http://127.0.0.1:%d/chat" % cls.srv.server_port

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def test_http_round_trip_with_template_paths_and_env_header(self):
        os.environ["AIG_TEST_TOKEN"] = "t0k"
        t = HttpTarget({"url": self.url, "headers": {"Authorization": "Bearer ${AIG_TEST_TOKEN}"},
                        "body": {"input": {"text": "{{message}}"}}, "response_path": "data.reply"})
        r = run(t, demo_ctx(), select(["AG01"]))
        self.assertEqual(r.findings[0].status, "fail")
        self.assertEqual(self.srv.seen_auth, "Bearer t0k")

    def test_http_skips_action_probe_without_actions_path(self):
        t = HttpTarget({"url": self.url, "body": {"input": {"text": "{{message}}"}}, "response_path": "data.reply"})
        r = run(t, demo_ctx(), select(["AG07"]))
        self.assertEqual(r.findings[0].status, "skipped")

    def test_bad_response_path_is_error(self):
        t = HttpTarget({"url": self.url, "body": {"input": {"text": "{{message}}"}}, "response_path": "nope"})
        self.assertIn("not found", t.send(Scenario("hi")).error)

    def test_unreachable_target_is_error(self):
        t = HttpTarget({"url": "http://127.0.0.1:9/x"}, timeout=2)
        self.assertTrue(t.send(Scenario("hi")).error)

    def test_missing_env_var_is_rejected(self):
        with self.assertRaises(ValueError):
            HttpTarget({"url": self.url, "headers": {"X": "${AIG_NOT_SET_123}"}})

    def test_dig(self):
        self.assertEqual(_dig({"a": [{"b": "x"}]}, "a.0.b"), "x")


class CliAndReportTests(unittest.TestCase):
    def test_exit_codes(self):
        self.assertEqual(run_cli("run", "--demo", "vulnerable")[0], 1)
        self.assertEqual(run_cli("run", "--demo", "guarded")[0], 0)
        self.assertEqual(run_cli("run", "--demo", "vulnerable", "--fail-on", "none")[0], 0)

    def test_http_requires_permission_flag(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"url": "http://127.0.0.1:9/x"}, fh)
        code, _, err = run_cli("run", "--http", fh.name)
        os.unlink(fh.name)
        self.assertEqual(code, 2)
        self.assertIn("permission", err)

    def test_bad_config_file(self):
        self.assertEqual(run_cli("run", "--demo", "guarded", "--config", "/no/such.json")[0], 2)

    def test_reports_written_and_escaped(self):
        d = tempfile.mkdtemp()
        h, j = os.path.join(d, "r.html"), os.path.join(d, "r.json")
        run_cli("run", "--demo", "vulnerable", "--html", h, "--json", j)
        with open(h, encoding="utf-8") as fh:
            html = fh.read()
        self.assertNotIn("<img src=x onerror", html)          # attacker text is escaped
        self.assertIn("&lt;img src=x onerror", html)
        with open(j, encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(data["summary"]["fail"], len(PROBES))

    def test_list(self):
        code, out, _ = run_cli("list")
        self.assertEqual(code, 0)
        self.assertIn("AG10", out)


if __name__ == "__main__":
    unittest.main()
