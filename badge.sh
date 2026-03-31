#!/bin/bash
# Generate a shields.io badge URL from a Sentinel scan result
# Usage: sentinel scan <url> --json | bash badge.sh
#        badge.sh A 94
#        badge.sh  (reads from stdin JSON)

set -uo pipefail

GRADE="${1:-}"
SCORE="${2:-}"

# If no args, read from stdin (piped JSON)
if [[ -z "$GRADE" ]]; then
  JSON=$(cat)
  GRADE=$(echo "$JSON" | python3 -c "import sys,json; print(json.load(sys.stdin).get('grade','?'))" 2>/dev/null)
  SCORE=$(echo "$JSON" | python3 -c "import sys,json; print(json.load(sys.stdin).get('score',0))" 2>/dev/null)
fi

# Color based on grade
case "$GRADE" in
  A) COLOR="brightgreen" ;;
  B) COLOR="green" ;;
  C) COLOR="yellow" ;;
  D) COLOR="orange" ;;
  F) COLOR="red" ;;
  *) COLOR="lightgrey" ;;
esac

BADGE_URL="https://img.shields.io/badge/Sentinel-${GRADE}%20(${SCORE}%25)-${COLOR}?style=flat&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IiNmNTllMGIiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48cGF0aCBkPSJNMTIgMjJzOC00IDgtMTBWNWwtOC0zLTggM3Y3YzAgNiA4IDEwIDggMTB6Ii8+PC9zdmc+"

# Markdown
MD_BADGE="[![Sentinel Grade](${BADGE_URL})](https://sentinel.hitcreate.io)"

echo "Badge URL:"
echo "  $BADGE_URL"
echo ""
echo "Markdown (paste in README):"
echo "  $MD_BADGE"
echo ""
echo "HTML:"
echo "  <a href=\"https://sentinel.hitcreate.io\"><img src=\"${BADGE_URL}\" alt=\"Sentinel Grade\"></a>"
