#!/usr/bin/env bash
#
# Stage-3 handler: HTTP(S) service enumeration (read-only).
#
# Registration:
#     HANDLES="http https"
# Only the nmap services listed here get handled.
#
# Usage (called by the dispatcher with exactly these arguments):
#   <handler> <stage2_xml> <target> <port> <protocol> \
#             <service> <product> <version> <outdir>
#
# Writes into <outdir>:
#   status.txt   - status=ok|skipped-dependency:curl|skipped|error + note
#   http_headers.txt
#   body.html    (verbatim response body - kept as evidence)
#
# SAFETY: performs a single read-only GET only. It never POSTs, PUTs,
# publishes, authenticates, or touches any stateful action. If 'curl' is
# absent the handler reports 'skipped-dependency:curl', never fails.

set -uo pipefail

HANDLES="http https"

if [[ $# -lt 8 ]]; then
    echo "status=error" > "$8/status.txt" 2>/dev/null || exit 1
    exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
    echo "status=skipped-dependency:curl" > "$8/status.txt"
    echo "note=curl is not installed; HTTP enumeration cannot run" >> "$8/status.txt"
    exit 0
fi

TARGET="$2"
PORT="$3"
SERVICE="$5"
OUTDIR="$8"

SCHEME="http"
[[ "$SERVICE" == "https" ]] && SCHEME="https"

URL="$SCHEME://$TARGET:$PORT/"

HEADERS="$OUTDIR/http_headers.txt"
BODY="$OUTDIR/body.html"

# Belt-and-suspenders bound on top of the dispatcher's outer 'timeout'.
MAX_TIME="${CURL_MAX_TIME:-20}"

curl -sS -L --max-time "$MAX_TIME" -o "$BODY" \
    -D "$HEADERS" -H "User-Agent: security-assessment-stage3 (read-only)" "$URL"
RC=$?

if (( RC == 0 )); then
    {
        echo "status=ok"
        echo "note=read-only GET on $URL"
        echo "curl_exit=0"
    } > "$OUTDIR/status.txt"
elif (( RC == 28 )); then
    echo "status=error" > "$OUTDIR/status.txt"
    echo "note=curl timed out on $URL (bounded by CURL_MAX_TIME=$MAX_TIME)" >> "$OUTDIR/status.txt"
    echo "curl_exit=28" >> "$OUTDIR/status.txt"
else
    echo "status=error" > "$OUTDIR/status.txt"
    echo "note=curl failed with exit $RC on $URL" >> "$OUTDIR/status.txt"
    echo "curl_exit=$RC" >> "$OUTDIR/status.txt"
fi

exit 0