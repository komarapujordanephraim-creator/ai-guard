"""Data passed between probes, targets and the report."""
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Scenario:
    """One conversation turn sent to the target.

    user_message: what the end user types.
    document: optional untrusted content the app reads (an email, a web page,
        an uploaded file). HTTP targets receive it inside the user message.
    tool_output: optional untrusted text returned by a tool or retrieval step.
    """
    user_message: str
    document: Optional[str] = None
    tool_output: Optional[str] = None

    def as_single_message(self) -> str:
        """Flatten the scenario for chat endpoints that take one message."""
        parts = [self.user_message]
        if self.document:
            parts.append("\n\n--- document ---\n" + self.document + "\n--- end document ---")
        if self.tool_output:
            parts.append("\n\n--- tool result ---\n" + self.tool_output + "\n--- end tool result ---")
        return "".join(parts)


@dataclass
class Action:
    """A side effect the app performed or requested (refund, email, delete...)."""
    name: str
    confirmed: bool = False
    args: Dict[str, str] = field(default_factory=dict)


@dataclass
class Response:
    text: str
    actions: List[Action] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class Finding:
    probe_id: str
    title: str
    category: str
    severity: str
    status: str            # "fail", "pass", "skipped", "error"
    evidence: str = ""
    why: str = ""
    fix: str = ""
    prompt: str = ""
