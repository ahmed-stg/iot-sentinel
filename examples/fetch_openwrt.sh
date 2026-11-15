#!/bin/sh
# Download the OpenWrt demo rootfs (same release as the paper corpus).
# The file is gitignored; commit the checksum, not the binary.
set -e
REL=25.12.6
URL="https://downloads.openwrt.org/releases/${REL}/targets/x86/64/openwrt-${REL}-x86-64-rootfs.tar.gz"
OUT="$(dirname "$0")/openwrt-rootfs.tar.gz"
SHA=55e52bb34de582a1ebe56bd50f94ff54ac7c77f5bca9cae807656d1930456da4

if [ -f "$OUT" ]; then
  echo "already downloaded: $OUT"
  exit 0
fi
echo "downloading $URL"
if command -v curl >/dev/null 2>&1; then
  curl -sL --fail -o "$OUT" "$URL"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$OUT" "$URL"
else
  # stdlib fallback (python3 is a hard requirement of the tool anyway)
  python3 - "$URL" "$OUT" <<'EOF'
import sys, urllib.request
url, out = sys.argv[1], sys.argv[2]
req = urllib.request.Request(url, headers={"User-Agent": "iotsentinel-fetch"})
with urllib.request.urlopen(req, timeout=300) as r, open(out, "wb") as f:
    f.write(r.read())
EOF
fi
echo "sha256:"
sha256sum "$OUT" 2>/dev/null || python3 -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest()+'  '+sys.argv[1])" "$OUT"
echo "expected: $SHA"
