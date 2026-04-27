"""Wk-2 framework-stack verification harness.

Smoke test that proves LangGraph + ChatOpenAI@OpenRouter + langchain-mcp-adapters
+ PostgresSaver compose. Exists to fail fast before sinking days into MCP Splunk
implementation. Throwaway scaffold — deletable post-wk-6 once the production
StateGraph lands.

CLI: `python -m sentient_orchestrator.verify`
Tests: `apps/orchestrator/tests/test_verify_smoke.py`
"""
