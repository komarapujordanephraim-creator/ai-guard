"""Console, JSON and HTML output. Everything from the target is escaped:
the evidence is attacker-controlled text by definition."""
import json
from dataclasses import asdict
from html import escape

from . import __version__
from .runner import RunResult

_LABEL = {"fail": "FAIL", "review": "REVIEW", "error": "ERROR", "pass": "pass", "skipped": "skip"}


def to_console(r: RunResult, color: bool = True) -> str:
    c = {"fail": "\033[31m", "review": "\033[33m", "error": "\033[35m", "pass": "\033[32m", "skipped": "\033[90m"}
    reset = "\033[0m" if color else ""
    lines = ["AI Guard %s  target: %s" % (__version__, r.target), ""]
    for f in r.findings:
        tag = _LABEL[f.status].ljust(6)
        if color:
            tag = c[f.status] + tag + reset
        lines.append("  %s %s  %-8s %s" % (tag, f.probe_id, f.severity, f.title))
        if f.status in ("fail", "review", "error") and f.evidence:
            lines.append("           evidence: %s" % f.evidence.replace("\n", " ")[:160])
    lines += ["", "  %d failed, %d to review, %d passed, %d skipped, %d errors" % (
        r.count("fail"), r.count("review"), r.count("pass"), r.count("skipped"), r.count("error"))]
    return "\n".join(lines)


def to_json(r: RunResult) -> str:
    return json.dumps({"tool": "ai-guard", "version": __version__, "target": r.target, "started": r.started,
                       "summary": {s: r.count(s) for s in ("fail", "review", "pass", "skipped", "error")},
                       "findings": [asdict(f) for f in r.findings]}, indent=2)


_CSS = """
:root{--bg:#06080d;--panel:#0f1520;--line:#222c3c;--fg:#eef2f8;--mute:#9aa4b6;--cy:#7de3ff;--cu:#ff9a5c;
--fail:#ff5c7a;--review:#ffd36e;--pass:#5be3a1;--skip:#6b7487;--err:#c49bff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 "Segoe UI",system-ui,sans-serif}
.wrap{max-width:1040px;margin:0 auto;padding:40px max(16px,env(safe-area-inset-left))}
.kick{font:600 11px/1 ui-monospace,Consolas,monospace;letter-spacing:.25em;text-transform:uppercase;color:var(--cu)}
h1{font-size:clamp(30px,5vw,46px);margin:.3em 0 .1em;letter-spacing:-.02em}
h1 span{background:linear-gradient(90deg,var(--cy),#fff,var(--cu));-webkit-background-clip:text;background-clip:text;color:transparent}
.meta{color:var(--mute);font-size:13px}
.tiles{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:28px 0}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px;cursor:pointer;text-align:left;color:inherit;font:inherit}
.tile b{display:block;font-size:30px;line-height:1.1}.tile small{color:var(--mute);text-transform:uppercase;letter-spacing:.12em;font-size:11px}
.tile[aria-pressed=true]{outline:2px solid var(--cy)}
.t-fail b{color:var(--fail)}.t-review b{color:var(--review)}.t-pass b{color:var(--pass)}.t-skipped b{color:var(--skip)}.t-error b{color:var(--err)}
.f{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--skip);border-radius:12px;margin:10px 0;overflow:hidden}
.f.fail{border-left-color:var(--fail)}.f.review{border-left-color:var(--review)}.f.pass{border-left-color:var(--pass)}.f.error{border-left-color:var(--err)}
summary{display:flex;gap:12px;align-items:center;padding:14px 16px;cursor:pointer;list-style:none}
summary::-webkit-details-marker{display:none}
.st{font:700 11px/1 ui-monospace,Consolas,monospace;padding:5px 8px;border-radius:6px;background:var(--line);min-width:62px;text-align:center}
.fail .st{background:var(--fail);color:#1a0006}.review .st{background:var(--review);color:#1d1400}.pass .st{background:var(--pass);color:#00140a}.error .st{background:var(--err);color:#12001f}
.id{font-family:ui-monospace,Consolas,monospace;color:var(--mute);font-size:12px}.sev{margin-left:auto;font-size:12px;color:var(--mute);text-transform:uppercase;letter-spacing:.1em}
.body{padding:0 16px 16px 90px;color:var(--mute)}.body h4{margin:12px 0 4px;color:var(--fg);font-size:13px}
pre{white-space:pre-wrap;word-break:break-word;background:#0a0f17;border:1px solid var(--line);border-radius:8px;padding:10px;color:#d7e3f4;font:12.5px/1.5 ui-monospace,Consolas,monospace;margin:0}
.note{margin-top:30px;color:var(--mute);font-size:13px;border-top:1px solid var(--line);padding-top:16px}
@media (max-width:700px){.tiles{grid-template-columns:repeat(2,1fr)}.body{padding-left:16px}}
"""

_JS = """
document.querySelectorAll('.tile').forEach(t=>t.addEventListener('click',()=>{
 const on=t.getAttribute('aria-pressed')!=='true';document.querySelectorAll('.tile').forEach(x=>x.setAttribute('aria-pressed','false'));
 t.setAttribute('aria-pressed',on);document.querySelectorAll('.f').forEach(f=>{f.hidden=on&&!f.classList.contains(t.dataset.s)});}));
"""


def to_html(r: RunResult) -> str:
    tiles = "".join(
        '<button class="tile t-%s" data-s="%s" aria-pressed="false"><b>%d</b><small>%s</small></button>'
        % (s, s, r.count(s), {"fail": "Failed", "review": "Review", "pass": "Passed", "skipped": "Skipped", "error": "Errors"}[s])
        for s in ("fail", "review", "pass", "skipped", "error"))
    items = []
    for f in r.findings:
        body = ["<h4>What happened</h4><p>%s</p>" % escape(f.why if f.status in ("fail", "review") else
                                                         {"pass": "The app did not follow the injected instruction.",
                                                          "skipped": "Not run: %s." % f.evidence,
                                                          "error": "The request failed."}.get(f.status, ""))]
        if f.status in ("fail", "review", "error") and f.evidence:
            body.append("<h4>Evidence</h4><pre>%s</pre>" % escape(f.evidence))
        if f.prompt:
            body.append("<h4>Test input sent</h4><pre>%s</pre>" % escape(f.prompt))
        body.append("<h4>How to fix</h4><p>%s</p>" % escape(f.fix))
        items.append('<details class="f %s"%s><summary><span class="st">%s</span><span><span class="id">%s</span> %s</span>'
                     '<span class="sev">%s</span></summary><div class="body">%s</div></details>'
                     % (f.status, " open" if f.status == "fail" else "", _LABEL[f.status].upper(), escape(f.probe_id),
                        escape(f.title), escape(f.severity), "".join(body)))
    return ("<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            "<title>AI Guard report</title><style>%s</style></head><body><div class=wrap>"
            "<div class=kick>AI Guard %s &middot; LLM app security test</div><h1>Security <span>report</span></h1>"
            "<div class=meta>Target: %s &middot; %s</div><div class=tiles>%s</div>%s"
            "<p class=note>Automated tests catch common failures; a pass does not prove an app is safe. "
            "Run only against systems you own or have written permission to test.</p></div><script>%s</script></body></html>"
            % (_CSS, __version__, escape(r.target), escape(r.started), tiles, "".join(items), _JS))
