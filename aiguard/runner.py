"""Runs the probes against a target and collects findings."""
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, List, Optional

from .probes import PROBES, Context, Probe
from .scenario import Finding
from .targets import Target

ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class RunResult:
    target: str
    started: str
    findings: List[Finding] = field(default_factory=list)

    def count(self, status: str) -> int:
        return sum(1 for f in self.findings if f.status == status)

    def worst_failure(self) -> Optional[str]:
        fails = [f.severity for f in self.findings if f.status == "fail"]
        return min(fails, key=lambda s: ORDER[s]) if fails else None


def select(only: Optional[Iterable[str]] = None) -> List[Probe]:
    if not only:
        return list(PROBES)
    wanted = {x.strip().upper() for x in only if x.strip()}
    unknown = wanted - {p.id for p in PROBES}
    if unknown:
        raise ValueError("unknown probe id(s): %s" % ", ".join(sorted(unknown)))
    return [p for p in PROBES if p.id in wanted]


def run(target: Target, ctx: Context, probes: Optional[List[Probe]] = None,
        delay: float = 0.0, max_requests: int = 100) -> RunResult:
    result = RunResult(target.name, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    sent = 0
    for probe in probes or PROBES:
        base = dict(probe_id=probe.id, title=probe.title, category=probe.category,
                    severity=probe.severity, why=probe.why, fix=probe.fix)
        scenario = probe.build(ctx)
        if probe.id == "AG07" and not target.reports_actions:
            scenario = None
        if scenario is None:
            result.findings.append(Finding(status="skipped", evidence="needs " + (probe.needs or "extra config"), **base))
            continue
        if sent >= max_requests:
            result.findings.append(Finding(status="skipped", evidence="request limit reached", **base))
            continue
        if sent and delay:
            time.sleep(delay)
        sent += 1
        resp = target.send(scenario)
        prompt = scenario.as_single_message()
        if resp.error:
            result.findings.append(Finding(status="error", evidence=resp.error, prompt=prompt, **base))
            continue
        status, evidence = probe.check(resp, ctx)
        result.findings.append(Finding(status=status, evidence=evidence, prompt=prompt, **base))
    result.findings.sort(key=lambda f: ({"fail": 0, "review": 1, "error": 2, "pass": 3, "skipped": 4}[f.status],
                                        ORDER[f.severity], f.probe_id))
    return result
