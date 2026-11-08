"""Example python target. Replace the body with a call into your own app,
using a TEST configuration (test database, test API keys).

Run:  python -m aiguard run --python examples.my_app:chat --config examples/config.example.json
"""
from aiguard.scenario import Response, Scenario


def chat(s: Scenario) -> Response:
    # Example only: call your real pipeline here, e.g.
    #   answer = my_assistant.handle(user_text=s.user_message,
    #                                retrieved_docs=[s.document] if s.document else [],
    #                                tool_results=[s.tool_output] if s.tool_output else [])
    #   return Response(answer.text, [Action(a.name, a.confirmed) for a in answer.actions])
    return Response("I can help with orders and returns.")
