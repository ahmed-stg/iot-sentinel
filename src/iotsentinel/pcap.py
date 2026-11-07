"""pcap: classic libpcap reader plus minimal protocol decoding.

Supports the classic libpcap format written by `tcpdump -w` and
Wireshark ("Save as pcap"), both byte orders; pcapng is explicitly NOT
supported (documented limitation). Frames are decoded only as far as the
MUD generation needs: Ethernet, 802.1Q VLAN tags, ARP, IPv4, IPv6, TCP,
UDP and DNS (queries and answers, so IP addresses can be mapped to
domain names). Anything unparseable is ignored, never fatal.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_ARP = 0x0806


@dataclass
class DnsRecord:
    name: str
    rtype: int
    data: str


@dataclass
class Packet:
    ts: float
    src_mac: str
    dst_mac: str
    ethertype: int
    src_ip: str = ""
    dst_ip: str = ""
    proto: int = 0          # IP protocol number: 6 TCP, 17 UDP, 1 ICMP
    sport: int = 0
    dport: int = 0
    tcp_flags: int = 0
    payload_len: int = 0
    dns: list[DnsRecord] = field(default_factory=list)
    dns_query: str = ""


def mac_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def read_pcap(path: str | Path):
    """Yield (timestamp, Packet) for every frame in a classic pcap file."""
    with open(path, "rb") as f:
        header = f.read(24)
        if len(header) < 24:
            raise ValueError("not a pcap file (short global header)")
        magic = header[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            endian = "<"
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian = ">"
        elif magic == b"\x4d\x3c\xb2\xa1":      # nanosecond variants
            endian = "<"
        elif magic == b"\xa1\xb2\x3c\x4d":
            endian = ">"
        else:
            raise ValueError("not a classic pcap file "
                             "(bad magic; pcapng is not supported)")
        linktype = struct.unpack(endian + "I", header[20:24])[0]
        if linktype != 1:                        # DLT_EN10MB
            raise ValueError("only Ethernet captures (linktype 1) are "
                             f"supported, got linktype {linktype}")
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                break
            ts_s, ts_us, incl, _orig = struct.unpack(endian + "IIII", rec)
            frame = f.read(incl)
            if len(frame) < incl:
                break                            # truncated record
            pkt = decode_frame(ts_s + ts_us / 1e6, frame)
            if pkt is not None:
                yield pkt


def decode_frame(ts: float, frame: bytes) -> Packet | None:
    if len(frame) < 14:
        return None
    dst_mac = mac_str(frame[0:6])
    src_mac = mac_str(frame[6:12])
    ethertype = struct.unpack(">H", frame[12:14])[0]
    offset = 14
    while ethertype == ETHERTYPE_VLAN and len(frame) >= offset + 4:
        ethertype = struct.unpack(">H", frame[offset + 2:offset + 4])[0]
        offset += 4
    pkt = Packet(ts=ts, src_mac=src_mac, dst_mac=dst_mac,
                 ethertype=ethertype)
    if ethertype == ETHERTYPE_ARP or ethertype not in (
            ETHERTYPE_IPV4, ETHERTYPE_IPV6):
        return None                            # L2 only: not needed for MUD
    if not decode_ip(ts, frame, offset, pkt):
        return None
    return pkt


def decode_ip(ts: float, frame: bytes, offset: int, pkt: Packet) -> bool:
    ip = frame[offset:]
    if pkt.ethertype == ETHERTYPE_IPV4:
        if len(ip) < 20:
            return False
        ihl = (ip[0] & 0x0F) * 4
        if ihl < 20 or len(ip) < ihl:
            return False
        pkt.proto = ip[9]
        pkt.src_ip = ".".join(str(b) for b in ip[12:16])
        pkt.dst_ip = ".".join(str(b) for b in ip[16:20])
        l4 = ip[ihl:]
    else:                                      # IPv6
        if len(ip) < 40:
            return False
        pkt.proto = ip[6]
        pkt.src_ip = _ipv6_str(ip[8:24])
        pkt.dst_ip = _ipv6_str(ip[24:40])
        l4 = ip[40:]
    if pkt.proto == 6:                         # TCP
        if len(l4) < 20:
            return False
        pkt.sport, pkt.dport = struct.unpack(">HH", l4[:4])
        pkt.tcp_flags = l4[13]
        doff = (l4[12] >> 4) * 4
        pkt.payload_len = max(0, len(l4) - doff)
    elif pkt.proto == 17:                      # UDP
        if len(l4) < 8:
            return False
        pkt.sport, pkt.dport = struct.unpack(">HH", l4[:4])
        pkt.payload_len = max(0, struct.unpack(">H", l4[4:6])[0] - 8)
    else:
        pkt.payload_len = max(0, len(l4))
        if pkt.proto not in (1, 58, 2):        # keep ICMP/ICMPv6/IGMP
            return False
    if pkt.dport == 53 and pkt.proto == 17:
        decode_dns(l4[8:], pkt, query=True)
    elif pkt.sport == 53 and pkt.proto == 17:
        decode_dns(l4[8:], pkt, query=False)
    return True


def _ipv6_str(b: bytes) -> str:
    import ipaddress
    return str(ipaddress.IPv6Address(b))


def decode_dns(msg: bytes, pkt: Packet, query: bool) -> None:
    """Best-effort DNS decoding: query names and A/AAAA/CNAME answers."""
    try:
        if len(msg) < 12:
            return
        qdcount = struct.unpack(">H", msg[4:6])[0]
        ancount = struct.unpack(">H", msg[6:8])[0]
        pos = 12
        for _ in range(qdcount):
            name, pos = read_dns_name(msg, pos)
            if pos + 4 > len(msg):
                return
            pos += 4
            if name:
                pkt.dns.append(DnsRecord(name, 0, "query"))
                pkt.dns_query = name
        for _ in range(ancount):
            name, pos = read_dns_name(msg, pos)
            if pos + 10 > len(msg):
                return
            rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", msg[pos:pos + 10])
            pos += 10
            rdata = msg[pos:pos + rdlen]
            pos += rdlen
            data = ""
            if rtype == 1 and rdlen == 4:
                data = ".".join(str(b) for b in rdata)
            elif rtype == 28 and rdlen == 16:
                data = _ipv6_str(rdata)
            elif rtype in (5, 2):
                data, _ = read_dns_name(msg, pos - rdlen)
            if name:
                pkt.dns.append(DnsRecord(name, rtype, data))
                if rtype in (1, 5, 28, 2):
                    pkt.dns_query = name
    except (struct.error, IndexError):
        return


def read_dns_name(msg: bytes, pos: int) -> tuple[str, int]:
    labels: list[str] = []
    jumps = 0
    end = pos
    while True:
        if pos >= len(msg) or jumps > 8:
            return ".".join(labels), end
        length = msg[pos]
        if length == 0:
            pos += 1
            end = max(end, pos)
            break
        if length & 0xC0 == 0xC0:              # compression pointer
            if pos + 1 >= len(msg):
                return ".".join(labels), end
            ptr = ((length & 0x3F) << 8) | msg[pos + 1]
            if ptr >= pos:
                return ".".join(labels), end   # forward pointer: malformed
            if not labels:
                end = pos + 2
            pos = ptr
            jumps += 1
            continue
        pos += 1
        label = msg[pos:pos + length]
        pos += length
        try:
            labels.append(label.decode("ascii", "strict").lower())
        except UnicodeDecodeError:
            labels.append("?.")
    return ".".join(labels) + "." if labels else "", end
