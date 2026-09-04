#!/usr/bin/env bash
# Build the encrypted site from ./books and push it. Usage: ./publish.sh ["commit message"]
set -euo pipefail
cd "$(dirname "$0")"
python3 build_reader.py
git add -A docs app build_reader.py publish.sh README.md .gitignore
if git diff --cached --quiet; then echo "Nothing new to publish."; exit 0; fi
git commit -q -m "${1:-Update library}"
git push
echo "Pushed. The site updates in about a minute."
