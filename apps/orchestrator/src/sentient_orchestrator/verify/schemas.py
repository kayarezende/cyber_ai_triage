"""State + structured-output models for the wk-2 verify graph."""

from __future__ import annotations

from typing import Annotated, TypedDict

from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages
from pydantic import BaseModel, Field


class ExtractedIP(BaseModel):
    """Structured-output target for the `extract_ip` node.

    The model is asked to extract a source IP from a synthetic Splunk event.
    Pinned-input + `temperature=0` + this Pydantic shape = deterministic
    verification of OpenRouter's structured-output passthrough on Gemini 3
    Flash.
    """

    src_ip: str = Field(..., description="Dotted-quad IPv4 source address.")


class VerifyState(TypedDict, total=False):
    """LangGraph state for the verify smoke graph.

    `total=False` so partial dicts returned from node functions merge cleanly.
    `messages` uses the standard add_messages reducer. The other two fields
    are populated by their respective nodes; absence means the node didn't
    run yet.
    """

    messages: Annotated[list[AnyMessage], add_messages]
    src_ip: str
    echo_result: str
