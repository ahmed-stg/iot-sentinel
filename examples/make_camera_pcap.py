#!/usr/bin/env python3
"""Generate a synthetic smart-camera pcap for the iotsentinel demo.

The capture mimics one device (default MAC aa:bb:cc:dd:ee:ff) on a home
LAN: DNS lookups answered by the gateway, HTTPS to a cloud endpoint,
NTP, and an inbound RTSP-like service on TCP/554. All addresses are
RFC 5737/1918 documentation addresses and the traffic is generated, not
captured: nothing here is private data.

Usage:
    python3 examples/make_camera_pcap.py out/camera.pcap [--v2]

`--v2` produces the post-"firmware update" capture used for the drift
demo: the NTP flow is gone and a new telemetry endpoint appears.
"""

from __future__ import annotations

import argparse
import struct

DEVICE_MAC = bytes.fromhex("aabbccddeeff")
GATEWAY_MAC = bytes.fromhex("aabbcc000001")
GATEWAY_IP = "192.168.1.1"
CAMERA_IP = "192.168.1.77"
CLIENT_IP = "192.168.1.50"
CLOUD_IP = "198.51.100.20"          # cloud.camera-vendor.com
NTP_IP = "203.0.113.10"             # ntp.camera-vendor.com
TELEMETRY_IP = "198.51.100.99"      # new in v2: telemetry.camera-vendor.com

PCAP_GLOBAL = (0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)   # LE magic, etherlink


def eth_ip_udp(src_mac, dst_mac, src_ip, dst_ip, sport, dport, payload):
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    return eth_ip(src_mac, dst_mac, src_ip, dst_ip, 17, udp)


def eth_ip_tcp(src_mac, dst_mac, src_ip, dst_ip, sport, dport, flags):
    tcp = struct.pack(">HHIIBBHHH", sport, dport, 1000, 2000, 5 << 4,
                      flags, 8192, 0, 0)
    return eth_ip(src_mac, dst_mac, src_ip, dst_ip, 6, tcp)


def eth_ip(src_mac, dst_mac, src_ip, dst_ip, proto, l4):
    total_len = 20 + len(l4)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total_len, 1234, 0, 64,
                     proto, 0,
                     bytes(int(x) for x in src_ip.split(".")),
                     bytes(int(x) for x in dst_ip.split(".")))
    return dst_mac + src_mac + b"\x08\x00" + ip + l4


def dns_message(qname: str, answer_ip: str | None) -> bytes:
    tid = 0x1234
    flags = 0x8180 if answer_ip else 0x0100
    qd = 1
    an = 1 if answer_ip else 0
    header = struct.pack(">HHHHHH", tid, flags, qd, an, 0, 0)
    q = b"".join(bytes([len(l)]) + l.encode() for l in qname.split("."))
    question = q + b"\x00" + struct.pack(">HH", 1, 1)
    if answer_ip:
        rr_name = b"\xc0\x0c"                       # pointer to question
        answer = (rr_name + struct.pack(">HHIH", 1, 1, 30, 4)
                  + bytes(int(x) for x in answer_ip.split(".")))
        return header + question + answer
    return header + question


def build_packets(v2: bool = False):
    """(timestamp, frame) tuples for one device's traffic."""
    out = []
    t = 1730000000.0

    def add(ts, frame):
        out.append((ts, frame))

    # DNS: cloud.camera-vendor.com -> CLOUD_IP
    for i in range(3):
        add(t, eth_ip_udp(DEVICE_MAC, GATEWAY_MAC, CAMERA_IP, GATEWAY_IP,
                          40000 + i, 53, dns_message(
                              "cloud.camera-vendor.com", None)))
        t += 0.01
        add(t, eth_ip_udp(GATEWAY_MAC, DEVICE_MAC, GATEWAY_IP, CAMERA_IP,
                          53, 40000 + i, dns_message(
                              "cloud.camera-vendor.com", CLOUD_IP)))
        t += 0.01
    # HTTPS to the cloud endpoint
    for i in range(5):
        add(t, eth_ip_tcp(DEVICE_MAC, GATEWAY_MAC, CAMERA_IP, CLOUD_IP,
                          41000 + i, 443, 0x02))
        t += 1.0
        add(t, eth_ip_tcp(GATEWAY_MAC, DEVICE_MAC, CLOUD_IP, CAMERA_IP,
                          443, 41000 + i, 0x12))
        t += 0.05
    # NTP to ntp.camera-vendor.com (dropped in v2)
    if not v2:
        add(t, eth_ip_udp(DEVICE_MAC, GATEWAY_MAC, CAMERA_IP, GATEWAY_IP,
                          42000, 53, dns_message(
                              "ntp.camera-vendor.com", None)))
        t += 0.01
        add(t, eth_ip_udp(GATEWAY_MAC, DEVICE_MAC, GATEWAY_IP, CAMERA_IP,
                          53, 42000, dns_message(
                              "ntp.camera-vendor.com", NTP_IP)))
        t += 0.01
        for i in range(4):
            add(t, eth_ip_udp(DEVICE_MAC, GATEWAY_MAC, CAMERA_IP, NTP_IP,
                              42000 + i, 123, b"\x1b" + b"\x00" * 47))
            t += 7.0
    # inbound RTSP-like service on local TCP/554 from one client
    for i in range(4):
        add(t, eth_ip_tcp(CLIENT_IP and GATEWAY_MAC, DEVICE_MAC, CLIENT_IP,
                          CAMERA_IP, 50000 + i, 554, 0x02))
        t += 2.0
        add(t, eth_ip_tcp(DEVICE_MAC, GATEWAY_MAC, CAMERA_IP, CLIENT_IP,
                          554, 50000 + i, 0x12))
        t += 0.05
    # v2: new telemetry endpoint the old policy would block
    if v2:
        add(t, eth_ip_udp(DEVICE_MAC, GATEWAY_MAC, CAMERA_IP, GATEWAY_IP,
                          43000, 53, dns_message(
                              "telemetry.camera-vendor.com", None)))
        t += 0.01
        add(t, eth_ip_udp(GATEWAY_MAC, DEVICE_MAC, GATEWAY_IP, CAMERA_IP,
                          53, 43000, dns_message(
                              "telemetry.camera-vendor.com", TELEMETRY_IP)))
        t += 0.01
        for i in range(4):
            add(t, eth_ip_tcp(DEVICE_MAC, GATEWAY_MAC, CAMERA_IP,
                              TELEMETRY_IP, 44000 + i, 443, 0x02))
            t += 1.0
    return out


def write_pcap(path: str, packets) -> None:
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", *PCAP_GLOBAL))
        for ts, frame in packets:
            secs = int(ts)
            usecs = int((ts - secs) * 1_000_000)
            f.write(struct.pack("<IIII", secs, usecs, len(frame),
                                len(frame)))
            f.write(frame)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--v2", action="store_true",
                    help="post-firmware-update capture (for drift demos)")
    ap.add_argument("--mac", default="aa:bb:cc:dd:ee:ff")
    args = ap.parse_args()
    write_pcap(args.out, build_packets(v2=args.v2))
    n = len(build_packets(v2=args.v2))
    print(f"wrote {args.out}: {n} frames, device {args.mac}"
          + (" (v2: new telemetry endpoint, NTP removed)" if args.v2 else ""))


if __name__ == "__main__":
    main()
