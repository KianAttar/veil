#!/bin/sh
# Quick local server for testing — open http://localhost:3000
cd "$(dirname "$0")"
echo "Veil Demo Chat running at http://localhost:3000"
echo "Open in two tabs, pick different names, test the extension."
python3 -m http.server 3000
