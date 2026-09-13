#!/usr/bin/env python3
"""Example --sink-transform for `vigil scan`: real HTML entity-escaping, not vigil's built-in
static heuristic. Point --sink-transform at this (or your own app's actual escaper) so LLM05's
SinkSurvives payloads are scored against what a real HTML-escaping template would produce.

Usage: vigil scan --category llm05 --sink-transform examples/html-escape-sink.py ...
"""
import html
import sys

sys.stdout.write(html.escape(sys.stdin.read()))
