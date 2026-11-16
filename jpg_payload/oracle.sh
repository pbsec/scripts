#!/usr/bin/env bash
# Example oracle for jpg_payload.php --oracle
#
# An "oracle" reproduces the TARGET's image conversion so the tool can verify
# candidates against the exact encoder the target uses. It reads a JPEG on STDIN
# and writes the converted JPEG to STDOUT.
#
# Why this matters: the injected bytes must be a FIXED POINT of the target's
# decode->encode cycle, which depends on the target's libjpeg version and encode
# params. Verifying with a different encoder finds payloads that won't survive.
#
# Match these to your target (read them off a processed sample with --analyze):
#   QUALITY   - JPEG quality the target encodes at (e.g. 90)
#   SAMPLE    - chroma subsampling: 2x2 = 4:2:0 (default), 1x1 = 4:4:4
#   PROGR     - set to 1 if the target emits progressive JPEGs (SOF2)
#
# This template uses cjpeg/djpeg from libjpeg(-turbo). If your target's libjpeg
# version differs from the one on your PATH, build a matching cjpeg/djpeg (or use
# a Docker container whose PHP-GD matches) and point DJPEG/CJPEG at them.
set -euo pipefail

DJPEG="${DJPEG:-djpeg}"      # override to a specific build, e.g. ./v8/djpeg
CJPEG="${CJPEG:-cjpeg}"
QUALITY="${QUALITY:-90}"
SAMPLE="${SAMPLE:-2x2}"      # 2x2 = 4:2:0, 1x1 = 4:4:4
PROGR="${PROGR:-0}"          # 1 -> progressive

args=(-quality "$QUALITY" -sample "$SAMPLE")
[ "$PROGR" = "1" ] && args+=(-progressive)

"$DJPEG" 2>/dev/null | "$CJPEG" "${args[@]}" 2>/dev/null
