"""Pydantic v2 contracts for siem_* tool inputs + outputs.

Each tool gets its own module so golden tests can import the model from a
stable path. Output models share `SiemEvent` (defined in `siem_query.py`) so
schema drift on Splunk's `_raw`/`_time` shape lights up one place.
"""
