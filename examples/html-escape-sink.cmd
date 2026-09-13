@echo off
REM Windows equivalent of html-escape-sink.py -- Command::new() on Windows honors .cmd/.bat
REM directly (unlike .py, which needs a shebang the OS loader doesn't understand), so this is
REM the form to point --sink-transform at on Windows.
python -c "import sys, html; sys.stdout.write(html.escape(sys.stdin.read()))"
