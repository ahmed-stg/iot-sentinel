#!/bin/sh
# Demo: run the full pipeline on the bundled example data, offline.
# The snapshot and the synthetic pcaps are committed; the firmware
# image is downloaded by examples/fetch_openwrt.sh (needs network, once).
set -e
cd /work
mkdir -p out

if [ ! -f examples/openwrt-rootfs.tar.gz ]; then
  echo "== 0. fetching the OpenWrt rootfs (checksummed) =="
  ./examples/fetch_openwrt.sh
fi

echo "== 1. SBOM from the OpenWrt rootfs =="
iotsentinel scan examples/openwrt-rootfs.tar.gz -o out/sbom.cdx.json

echo "== 2. Ranked triage on the pinned snapshot =="
iotsentinel triage out/sbom.cdx.json --snapshot data/snapshots/2026-11-15 \
    --weights W1 -o out/triage.json --html out/triage.html

echo "== 3. MUD file from the synthetic capture =="
iotsentinel mudgen examples/camera.pcap --mac aa:bb:cc:dd:ee:ff \
    -o out/camera.mud.json

echo "== 4. nftables ruleset, safety-critical device =="
iotsentinel enforce out/camera.mud.json --risk out/triage.json \
    --class safety-critical -o out/camera.nft

echo "done; outputs in out/"
