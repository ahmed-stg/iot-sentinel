# Examples

Everything here is either a script that fetches/generates data, or small
generated files. No firmware image, no large feed, no private capture is
committed to this repository.

## OpenWrt rootfs

The demo uses the same release as the `sbom_firmware` preprint corpus:
OpenWrt 25.12.6, x86-64 rootfs.

```bash
./fetch_openwrt.sh                 # downloads examples/openwrt-rootfs.tar.gz
sha256sum examples/openwrt-rootfs.tar.gz
# expected:
# 55e52bb34de582a1ebe56bd50f94ff54ac7c77f5bca9cae807656d1930456da4  examples/openwrt-rootfs.tar.gz
```

The tarball itself is gitignored; only the checksum and the fetch script
are committed.

## Synthetic camera capture

`make_camera_pcap.py` generates the demo pcaps: one device
(`aa:bb:cc:dd:ee:ff`), DNS through the gateway, HTTPS to a cloud
endpoint, NTP, an inbound RTSP-like service. All addresses are RFC 5737
documentation addresses and the traffic is generated, not captured, so
there is no private data and no licensing issue. `--v2` produces the
post-"firmware update" capture used for the drift demo (new telemetry
endpoint, NTP flow gone).

```bash
python3 make_camera_pcap.py out/camera.pcap
python3 make_camera_pcap.py out/camera-v2.pcap --v2
```

## Synthetic rootfs (tests)

`tests/` builds a tiny synthetic rootfs in a temporary directory; no
fixture file is needed.
