#!/bin/sh
# Download the OpenWrt demo rootfs (same release as the paper corpus).
# The file is gitignored; commit the checksum, not the binary.
set -e
REL=25.12.6
URL="https://downloads.openwrt.org/releases/${REL}/targets/x86/64/openwrt-${REL}-x86-64-rootfs.tar.gz"
OUT="$(dirname "$0")/openwrt-rootfs.tar.gz"

if [ -f "$OUT" ]; then
  echo "already downloaded: $OUT"
  exit 0
fi
echo "downloading $URL"
curl -sL --fail -o "$OUT" "$URL"
echo "sha256:"
sha256sum "$OUT"
echo "expected: 55e52bb34de582a1ebe56bd50f94ff54ac7c77f5bca9cae807656d1930456da4"
