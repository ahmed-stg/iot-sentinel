"""Tests for the pcap reader: classic libpcap decoding, DNS, VLAN."""

import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "examples"))
from make_camera_pcap import build_packets, write_pcap  # noqa: E402

from iotsentinel.pcap import decode_frame, read_pcap  # noqa: E402


def write_tmp(packets):
    tmp = tempfile.TemporaryDirectory()
    path = Path(tmp.name) / "t.pcap"
    write_pcap(str(path), packets)
    return tmp, path


class TestPcapReader(unittest.TestCase):
    def test_read_camera_pcap(self):
        tmp, path = write_tmp(build_packets())
        try:
            packets = list(read_pcap(path))
        finally:
            tmp.cleanup()
        self.assertEqual(len(packets), 30)
        first = packets[0]
        self.assertEqual(first.src_mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(first.dst_ip, "192.168.1.1")
        self.assertEqual(first.dport, 53)
        self.assertEqual(first.proto, 17)

    def test_dns_answers_mapped(self):
        tmp, path = write_tmp(build_packets())
        try:
            packets = list(read_pcap(path))
        finally:
            tmp.cleanup()
        names = [r.name for p in packets for r in p.dns]
        self.assertIn("cloud.camera-vendor.com.", names)
        answers = {r.data for p in packets for r in p.dns
                   if r.rtype == 1}
        self.assertIn("198.51.100.20", answers)

    def test_tcp_flow_present(self):
        tmp, path = write_tmp(build_packets())
        try:
            packets = list(read_pcap(path))
        finally:
            tmp.cleanup()
        syns = [p for p in packets if p.proto == 6 and p.dport == 443]
        self.assertTrue(syns)
        self.assertEqual(syns[0].dst_ip, "198.51.100.20")

    def test_bad_magic_raises(self):
        tmp = tempfile.TemporaryDirectory()
        path = Path(tmp.name) / "x.pcap"
        path.write_bytes(b"PCAPNG-LIKE" + b"\x00" * 40)
        try:
            with self.assertRaises(ValueError):
                list(read_pcap(path))
        finally:
            tmp.cleanup()

    def test_truncated_record_stops_cleanly(self):
        tmp, path = write_tmp(build_packets())
        try:
            blob = path.read_bytes()
            path.write_bytes(blob[:24 + 16 + 10])   # cut inside first frame
            packets = list(read_pcap(path))
            self.assertEqual(len(packets), 0)
        finally:
            tmp.cleanup()

    def test_vlan_tag_skipped(self):
        frame = (bytes.fromhex("aabbccddeeff") + bytes.fromhex("112233445566")
                 + b"\x81\x00" + b"\x00\x64" + b"\x08\x00")
        pkt = decode_frame(1.0, frame + b"\x00" * 40)
        self.assertIsNone(pkt)      # IP payload too short -> dropped, but
        # the VLAN tag was consumed without crash (ethertype parsed)

    def test_big_endian_pcap(self):
        packets = build_packets()[:2]
        tmp = tempfile.TemporaryDirectory()
        path = Path(tmp.name) / "be.pcap"
        with open(path, "wb") as f:
            f.write(struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0,
                                262144, 1))
            for ts, frame in packets:
                f.write(struct.pack(">IIII", int(ts), 0, len(frame),
                                    len(frame)))
                f.write(frame)
        try:
            got = list(read_pcap(path))
            self.assertEqual(len(got), 2)
        finally:
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
