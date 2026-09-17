#!/usr/bin/env bash
#
# Stage-3 handler: banner / NSE-evidence extraction (read-only).
#
# Method of registration: this file declares
#     HANDLES="*"
# which instructs the enumeration Stage-3 dispatcher to run it for every
# discovered service (or list specific nmap service names: "ftp ssh").
#
# Usage (called by the dispatcher with exactly these arguments):
#   <handler> <stage2_xml> <target> <port> <protocol> \
#             <service> <product> <version> <outdir>
#
# Writes into <outdir>:
#   status.txt  - status=ok|skipped|error + note
#   banner.txt  - NSE script banners + service-line evidence from the XML
#
# SAFETY: this handler only reads local artifacts and never opens a network
# connection or runs anything beyond XML inspection. It is POSIX-awk compatible
# (no gawk-only match() capture arrays).

set -uo pipefail

HANDLES="*"

if [[ $# -lt 8 ]]; then
    echo "status=error" > "$8/status.txt"
    echo "note=handler invoked with $# arguments (expected 8)" >> "$8/status.txt"
    exit 1
fi

XML="$1"
TARGET="$2"
PORT="$3"
PROTO="$4"
SERVICE="$5"
PRODUCT="$6"
VERSION="$7"
OUTDIR="$8"

BANNER="$OUTDIR/banner.txt"
STATUS="$OUTDIR/status.txt"

write_banner() {
    local awk_sel
    awk_sel='match($0, "<port protocol=\"" proto "\" portid=\"" port "\"") { prt=1 }
             prt && /<\/port>/ { prt=0 }
             prt { print }'

    local awk_nse
    awk_nse='match($0, "<port protocol=\"" proto "\" portid=\"" port "\"") { prt=1 }
              prt && /<\/port>/ { prt=0 }
              prt && index($0, "<script id=") {
                  s = $0
                  while (match(s, /<script id="[^"]*"[^>]*output="[^"]*"/)) {
                      seg = substr(s, RSTART, RLENGTH)
                      k = index(seg, "id=\"") + 4
                      k2 = index(substr(seg, k), "\"")
                      id = substr(seg, k, k2 - 1)
                      i = index(seg, "output=\"") + 8
                      j = index(substr(seg, i), "\"")
                      out = substr(seg, i, j - 1)
                      print "[" id "] " out
                      s = substr(s, RSTART + RLENGTH)
                  }
              }'

    {
        echo "# Stage-3 banner extraction ($(basename "$0"))"
        echo "# target=$TARGET"
        echo "# service=$SERVICE product=$PRODUCT version=$VERSION"
        echo
        echo "[port block]"
        awk -v port="$PORT" -v proto="$PROTO" "$awk_sel" "$XML" | sed -n '1,40p'
        echo
        echo "[NSE script outputs]"
        awk -v port="$PORT" -v proto="$PROTO" "$awk_nse" "$XML" \
            | sed 's/%[0-9A-Fa-f]\{2\}/ /g; s/\\n/ /g' | sed -n '1,60p'
    } > "$BANNER"
}

if [[ -s "$XML" ]] && command -v awk >/dev/null 2>&1; then
    if write_banner; then
        echo "status=ok" > "$STATUS"
        echo "note=banner.txt written from stage-2 XML evidence" >> "$STATUS"
        exit 0
    fi
    echo "status=error" > "$STATUS"
    echo "note=banner extraction failed" >> "$STATUS"
    exit 2
fi

echo "status=skipped" > "$STATUS"
echo "note=no Nmap XML artifact available; banner extraction requires stage-2 XML" >> "$STATUS"
exit 0