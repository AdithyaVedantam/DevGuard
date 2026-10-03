#!/usr/bin/env sh
# One-command start for Mac/Linux:  ./start.sh
set -e
cd "$(dirname "$0")"
[ -d .venv ] || python3 -m venv .venv
. .venv/bin/activate
pip install -q -r requirements.txt
echo "DevGuard running at http://localhost:8000   (Ctrl+C to stop)"
cd backend && uvicorn main:app --reload --port 8000
