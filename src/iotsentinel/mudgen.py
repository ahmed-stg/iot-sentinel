"""mudgen: pcap to RFC 8520 MUD definition.

For one device MAC, the distinct observed flows are collected (direction,
protocol, remote endpoint, DNS names learned from observed answers) and
turned into the two access lists of a MUD file (`from-device-policy` /
`to-device-policy`). Flows seen fewer than `--min-observations` times are
treated as noise, not rules.

`--compare old.mud.json new.pcap` runs the drift check from the
mud_adoption preprint: flows in the new capture that the old policy would
block (candidate false-blocks) and old rules the new capture never
exercises (candidate over-permissions).

Limitations, stated rather than hidden: the MUD only knows what the
capture shows (an incomplete capture gives a too-strict policy), classic
pcap only, and the generated file is a best-effort draft, not a
validated profile.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .pcap import Packet, read_pcap

# ports treated as local-device noise rather than policy-worthy endpoints
NOISE_REMOTE_PORTS = {67, 68, 5353}          # DHCP, mDNS
LOCAL_PORTS_KEEP = {53, 123, 1900, 5351, 554}     # DNS, NTP, SSDP, NAT-PMP, RTSP


def parse_mac(mac: str) -> str:
    mac = mac.strip().lower().replace("-", ":")
    parts = mac.split(":")
    if len(parts) != 6 or not all(len(p) == 2 for p in parts):
        raise ValueError(f"not a MAC address: {mac!r}")
    int(mac.replace(":", ""), 16)
    return mac


@dataclass
class Flow:
    direction: str            # "out" device->remote, "in" remote->device
    proto: str                # "tcp", "udp"
    remote_ip: str
    remote_port: int
    local_port: int
    dns_name: str = ""
    observations: int = 0


def is_link_local(ip: str) -> bool:
    return ip.startswith(("169.254.", "fe80:"))


def is_multicast(ip: str) -> bool:
    if ip.startswith("224.") or ip.startswith("239."):
        return True
    if ":" in ip:
        return ip.lower().startswith(("ff0", "ff1", "ff2"))
    return False


def attach_dns_answers(packets: list[Packet]) -> dict[str, str]:
    """Map resolved IP -> domain name from DNS answers in the capture."""
    ip_to_name: dict[str, str] = {}
    for pkt in packets:
        for rec in pkt.dns:
            if rec.rtype in (1, 28) and rec.data and \
                    not rec.name.endswith(".in-addr.arpa."):
                ip_to_name.setdefault(rec.data, rec.name)
    return ip_to_name


def flows_from_packets(packets: list[Packet], device_mac: str,
                       min_observations: int) -> list[Flow]:
    """Aggregate packets into policy-relevant flows. Outbound flows are
    keyed on (proto, remote ip, remote port) - the device's ephemeral
    source port is noise. Inbound flows are keyed on (proto, local port)
    - which client connected does not matter for a service rule."""
    device = parse_mac(device_mac)
    ip_to_name = attach_dns_answers(packets)
    flows: dict[tuple, Flow] = {}
    for pkt in packets:
        if pkt.src_mac != device and pkt.dst_mac != device:
            continue
        if pkt.proto not in (6, 17):
            continue
        proto = "tcp" if pkt.proto == 6 else "udp"
        if pkt.src_mac == device:
            direction, remote_ip, remote_port, local_port = \
                "out", pkt.dst_ip, pkt.dport, pkt.sport
        else:
            direction, remote_ip, remote_port, local_port = \
                "in", pkt.src_ip, pkt.sport, pkt.dport
        if direction == "out" and remote_port in NOISE_REMOTE_PORTS:
            continue
        if direction == "in" and local_port not in LOCAL_PORTS_KEEP:
            continue
        if direction == "in" and remote_port in NOISE_REMOTE_PORTS:
            continue
        if is_link_local(remote_ip) or is_multicast(remote_ip):
            continue
        if direction == "out":
            key = (direction, proto, remote_ip, remote_port)
        else:
            key = (direction, proto, local_port)
        flow = flows.setdefault(key, Flow(direction, proto, remote_ip,
                                          remote_port, local_port))
        flow.observations += 1
        if not flow.dns_name:
            flow.dns_name = ip_to_name.get(remote_ip, "")
    kept = [f for f in flows.values() if f.observations >= min_observations]
    kept.sort(key=lambda f: (f.direction, f.proto, f.remote_ip,
                             f.remote_port))
    return kept


def mud_url_for(mac: str) -> str:
    return f"https://mud.example.org/iotsentinel/{mac.replace(':', '')}.json"


def build_mud(device_mac: str, flows: list[Flow], systeminfo: str,
              cache_validity: int = 24 * 60 * 60) -> dict:
    """RFC 8520 MUD definition as JSON.

    Rule translation follows the RFC's example (section 9) exactly:
    DNS names are `ietf-acldns:dst-dnsname` leaves inside the
    `ipv4`/`ipv6` match object together with `protocol`; ports are
    `destination-port` `operator: eq` objects inside the `tcp`/`udp`
    match object; `ietf-mud:direction-initiated` sits in the protocol
    object; `from-device-policy`/`to-device-policy` name access lists
    as `{"name": ...}` objects.

    - an outbound flow to a DNS-learned name becomes a dst-dnsname rule
    - an outbound flow to a bare IP becomes a destination-*-network rule
    - an inbound flow to a kept local service becomes a to-device rule
    """
    acl_entries: list[dict] = []
    seen_names: set[str] = set()
    seen_ips: set[str] = set()
    seen_services: set[tuple] = set()

    for f in flows:
        proto_num = 6 if f.proto == "tcp" else 17
        proto_key = f.proto
        if f.direction == "out":
            if f.dns_name and f.dns_name not in seen_names:
                seen_names.add(f.dns_name)
                acl_entries.append({
                    "name": f"todev-{f.dns_name.rstrip('.').split('.')[0]}",
                    "type": "ipv4-acl-type",
                    "aces": {"ace": [{
                        "name": "cl0-frdev",
                        "matches": {
                            "ipv4": {
                                "protocol": proto_num,
                                "ietf-acldns:dst-dnsname": f.dns_name,
                            },
                            proto_key: {
                                "ietf-mud:direction-initiated":
                                    "from-device",
                                "destination-port": {
                                    "operator": "eq",
                                    "port": f.remote_port,
                                },
                            },
                        },
                        "actions": {"forwarding": "accept"},
                    }]},
                })
            elif not f.dns_name and (f.proto, f.remote_ip) not in seen_ips:
                seen_ips.add((f.proto, f.remote_ip))
                ip_key = ("destination-ipv6-network" if ":" in f.remote_ip
                          else "destination-ipv4-network")
                ip_obj = {"protocol": proto_num,
                          ip_key: f"{f.remote_ip}/128"
                          if ":" in f.remote_ip else f"{f.remote_ip}/32"}
                acl_entries.append({
                    "name": f"toip-{f.remote_ip}-{f.proto}-{f.remote_port}",
                    "type": ("ipv6-acl-type" if ":" in f.remote_ip
                             else "ipv4-acl-type"),
                    "aces": {"ace": [{
                        "name": "cl0-frdev",
                        "matches": {
                            ("ipv6" if ":" in f.remote_ip else "ipv4"):
                            ip_obj,
                            proto_key: {
                                "ietf-mud:direction-initiated":
                                    "from-device",
                                "destination-port": {
                                    "operator": "eq",
                                    "port": f.remote_port,
                                },
                            },
                        },
                        "actions": {"forwarding": "accept"},
                    }]},
                })
        else:                                  # inbound service on the device
            if f.local_port in LOCAL_PORTS_KEEP and \
                    (f.proto, f.local_port) not in seen_services:
                seen_services.add((f.proto, f.local_port))
                acl_entries.append({
                    "name": f"fromdev-{f.proto}-{f.local_port}",
                    "type": "ipv4-acl-type",
                    "aces": {"ace": [{
                        "name": "cl0-todev",
                        "matches": {
                            proto_key: {
                                "ietf-mud:direction-initiated":
                                    "to-device",
                                "destination-port": {
                                    "operator": "eq",
                                    "port": f.local_port,
                                },
                            },
                        },
                        "actions": {"forwarding": "accept"},
                    }]},
                })

    return {
        "ietf-mud:mud": {
            "mud-version": 1,
            "mud-url": mud_url_for(device_mac),
            "last-update": datetime.now(timezone.utc)
            .isoformat(timespec="seconds").replace("+00:00", "Z"),
            "cache-validity": cache_validity,
            "is-supported": True,
            "systeminfo": systeminfo or
            f"device learned by iotsentinel {__version__} "
            f"from a traffic capture ({len(flows)} flows)",
            "from-device-policy": {"access-lists": {"access-list": [
                {"name": a["name"]} for a in acl_entries
                if "frdev" in a["aces"]["ace"][0]["name"]
                or a["name"].startswith(("todev", "toip"))]}},
            "to-device-policy": {"access-lists": {"access-list": [
                {"name": a["name"]} for a in acl_entries
                if a["name"].startswith("fromdev")]}},
        },
        "ietf-access-control-list:acls": {
            "acl": acl_entries,
        },
    }


def ace_allows(ace: dict, flow: Flow) -> bool:
    """True if one ACE matches a flow (both direction and endpoints)."""
    matches = ace.get("matches", {})
    proto_key = flow.proto
    spec = matches.get(proto_key)
    if spec is None:
        return False
    dirn = spec.get("ietf-mud:direction-initiated", "")
    if dirn == "from-device" and flow.direction != "out":
        return False
    if dirn == "to-device" and flow.direction != "in":
        return False
    # L3 matches (dns names and networks) live in the ipv4/ipv6 object
    for ip_key, flow_ip in (("ipv4", flow.remote_ip),
                            ("ipv6", flow.remote_ip)):
        l3 = matches.get(ip_key)
        if l3 is None:
            continue
        proto = l3.get("protocol")
        if proto is not None and proto != (6 if flow.proto == "tcp" else 17):
            return False
        dns = l3.get("ietf-acldns:dst-dnsname")
        if dns is not None:
            if flow.dns_name.rstrip(".") != dns.rstrip("."):
                return False
        for net_key in ("destination-ipv4-network",
                        "destination-ipv6-network"):
            net = l3.get(net_key)
            if net is not None and not ip_in_network(flow.remote_ip, net):
                return False
    # the destination port of an inbound flow is the device's local port
    dest_port = flow.local_port if flow.direction == "in" \
        else flow.remote_port
    port_spec = spec.get("destination-port")
    if port_spec:
        if port_spec.get("operator", "eq") == "eq":
            if dest_port != port_spec.get("port"):
                return False
    return True


def acl_allows(flow: Flow, mud: dict) -> bool:
    """Would the MUD's access lists accept this flow? (for drift checks)"""
    aces = []
    for acl in mud.get("ietf-access-control-list:acls", {}) \
            .get("acl", []):
        aces += acl.get("aces", {}).get("ace", [])
    return any(ace_allows(ace, flow) for ace in aces)


def ip_in_network(ip: str, network: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(
            network, strict=False)
    except ValueError:
        return False


def drift_check(old_mud: dict, new_pcap: str, device_mac: str,
                min_observations: int = 2) -> dict:
    """Candidate false-blocks and over-permissions, as in the paper."""
    new_flows = flows_from_packets(
        list(read_pcap(new_pcap)), device_mac, min_observations)
    false_blocks = []
    for f in new_flows:
        if not acl_allows(f, old_mud):
            false_blocks.append(flow_str(f))
    exercised: set[str] = set()
    for f in new_flows:
        if acl_allows(f, old_mud):
            exercised.add(rule_key_for(f, old_mud))
    over_permissions = []
    for acl in old_mud.get("ietf-access-control-list:acls", {}) \
            .get("acl", []):
        name = acl.get("name", "")
        if name and name not in exercised:
            over_permissions.append(name)
    return {
        "flows_observed": len(new_flows),
        "candidate_false_blocks": sorted(set(false_blocks)),
        "candidate_over_permissions": over_permissions,
    }


def flow_str(f: Flow) -> str:
    return (f"{f.direction} {f.proto} {f.remote_ip}:{f.remote_port}"
            + (f" ({f.dns_name})" if f.dns_name else ""))


def rule_key_for(flow: Flow, mud: dict) -> str:
    """Name of the first ACL that would allow this flow, if any."""
    for acl in mud.get("ietf-access-control-list:acls", {}).get("acl", []):
        for ace in acl.get("aces", {}).get("ace", []):
            if ace_allows(ace, flow):
                return acl.get("name", "")
    return ""


def cmd_mudgen(args) -> int:
    try:
        device_mac = parse_mac(args.mac)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if not os.path.exists(args.pcap):
        print(f"error: pcap not found: {args.pcap}", file=sys.stderr)
        return 1
    try:
        packets = list(read_pcap(args.pcap))
    except (ValueError, OSError) as exc:
        print(f"error: cannot read capture: {exc}", file=sys.stderr)
        return 1
    flows = flows_from_packets(packets, device_mac, args.min_observations)
    mud = build_mud(device_mac, flows, systeminfo="")

    if args.compare:
        try:
            old_mud = json.loads(Path(args.compare).read_text(
                encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            print(f"error: cannot read old MUD: {exc}", file=sys.stderr)
            return 1
        drift = drift_check(old_mud, args.pcap, device_mac,
                            args.min_observations)
        print(f"drift vs {args.compare}: "
              f"{len(drift['candidate_false_blocks'])} candidate "
              f"false-blocks, "
              f"{len(drift['candidate_over_permissions'])} candidate "
              f"over-permissions "
              f"(of {drift['flows_observed']} observed flows)")
        for fb in drift["candidate_false_blocks"]:
            print(f"  would block: {fb}")
        for op in drift["candidate_over_permissions"]:
            print(f"  never exercised: {op}")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(mud, indent=2) + "\n", encoding="utf-8")
    def _n(side):
        return len(mud["ietf-mud:mud"][side]["access-lists"]
                   .get("access-list", []))
    print(f"MUD file written to {out}: {_n('from-device-policy')} "
          f"outbound rules, {_n('to-device-policy')} inbound rules")
    return 0
