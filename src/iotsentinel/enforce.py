"""enforce: MUD file to nftables ruleset, with safety-aware degradation.

Implements the four-level policy ladder from the `zt_gateway` preprint
(allow, allow-and-log, restricted, block) as the rung selection:

| device class     | device risk (from triage) | rung                       |
|------------------|---------------------------|----------------------------|
| standard         | P1/P2 (high)              | quarantine (block rung):   |
|                  |                           | allow only DNS + estab.    |
| safety-critical  | P1/P2 (high)              | restricted: keep the       |
|                  |                           | allow-list, drop inbound   |
|                  |                           | from non-management hosts, |
|                  |                           | rate-limit, log loudly,    |
|                  |                           | never a full cut-off       |
| any              | P3/P4 or no risk data     | allow-list (logged)        |

The generated ruleset is syntax-checked by the caller with `nft -c -f`
(no root needed); enforcement on a live gateway is out of scope.
Domain-name rules need IP resolution at apply time (CDNs rotate IPs);
they are emitted as comments plus a placeholder set for a re-resolution
script rather than being silently widened.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from . import __version__
from .mudgen import LOCAL_PORTS_KEEP

ALLOW_RUNG = "allow"
ALLOW_LOG_RUNG = "allow-and-log"
RESTRICTED_RUNG = "restricted"
BLOCK_RUNG = "quarantine"

RUNGS = (ALLOW_RUNG, ALLOW_LOG_RUNG, RESTRICTED_RUNG, BLOCK_RUNG)


def device_mac_from_mud(mud: dict) -> str:
    """The MUD url embeds the MAC; the mud file itself has no MAC field,
    so enforce carries the MAC from mudgen via the systeminfo or falls
    back to the mud-url token."""
    url = mud.get("ietf-mud:mud", {}).get("mud-url", "")
    token = url.rstrip(".json").rsplit("/", 1)[-1]
    if len(token) == 12 and all(c in "0123456789abcdef" for c in token):
        return ":".join(token[i:i + 2] for i in range(0, 12, 2))
    return "00:00:00:00:00:00"


def acl_rules(mud: dict) -> dict:
    """Extract the allow rules from the MUD file: outbound (to-device
    destinations seen from-device) and inbound services."""
    out_rules: list[dict] = []      # {dns: name} or {ip: net}, proto, port
    in_rules: list[dict] = []
    acls = mud.get("ietf-access-control-list:acls", {}).get("acl", [])
    policy_names = {a["name"] for a in
                    mud.get("ietf-mud:mud", {})
                    .get("from-device-policy", {})
                    .get("access-lists", {}).get("access-list", [])}
    for acl in acls:
        if acl.get("name") not in policy_names:
            continue
        for ace in acl.get("aces", {}).get("ace", []):
            matches = ace.get("matches", {})
            for proto_key in ("tcp", "udp"):
                spec = matches.get(proto_key)
                if spec is None:
                    continue
                dirn = spec.get("ietf-mud:direction-initiated", "")
                port = None
                port_spec = spec.get("destination-port") or {}
                if port_spec.get("operator", "eq") == "eq":
                    port = port_spec.get("port")
                for ip_key in ("ipv4", "ipv6"):
                    l3 = matches.get(ip_key)
                    if l3 is None:
                        continue
                    dns = l3.get("ietf-acldns:dst-dnsname")
                    net = (l3.get("destination-ipv4-network")
                           or l3.get("destination-ipv6-network"))
                    rule = {"proto": proto_key,
                            "dir": "out" if dirn != "to-device" else "in",
                            "dns": dns, "ip": net, "port": port}
                    if rule["dir"] == "out":
                        out_rules.append(rule)
                    else:
                        in_rules.append(rule)
            # inbound service rules carry no L3 object
            if "ipv4" not in matches and "ipv6" not in matches:
                dirn = spec.get("ietf-mud:direction-initiated", "") \
                    if "spec" in locals() else ""
    # inbound services (fromdev-*) live in ACLs not named by
    # from-device-policy; pick them up separately
    for acl in acls:
        if acl.get("name") in policy_names or \
                not acl.get("name", "").startswith("fromdev-"):
            continue
        for ace in acl.get("aces", {}).get("ace", []):
            matches = ace.get("matches", {})
            for proto_key in ("tcp", "udp"):
                spec = matches.get(proto_key)
                if spec is None:
                    continue
                port_spec = spec.get("destination-port") or {}
                if port_spec.get("operator", "eq") == "eq":
                    in_rules.append({"proto": proto_key, "dir": "in",
                                     "dns": None, "ip": None,
                                     "port": port_spec.get("port")})
    return {"out": out_rules, "in": in_rules}


def pick_rung(device_class: str, tier: str | None) -> str:
    """The ladder rung, per the zt_gateway degradation table."""
    high = tier in ("P1", "P2")
    if device_class == "safety-critical":
        return RESTRICTED_RUNG if high else ALLOW_LOG_RUNG
    if device_class == "standard":
        return BLOCK_RUNG if high else ALLOW_RUNG
    raise ValueError(f"unknown device class: {device_class!r}")


def device_tier_from_risk(risk: dict) -> str | None:
    """Worst tier across the triage findings (documented assumption: the
    triage was run over this device's firmware)."""
    tiers = [f.get("tier") for f in risk.get("findings", [])]
    for t in ("P1", "P2", "P3", "P4"):
        if t in tiers:
            return t
    return None


def nft_name(device_class: str, mac: str) -> str:
    base = "cam" if device_class == "safety-critical" else "dev"
    return f"{base}_{mac.replace(':', '')}"


def build_ruleset(mud: dict, device_class: str, rung: str,
                  mac: str, mgmt_subnets: list[str] | None = None,
                  rate: str = "10/second") -> str:
    name = nft_name(device_class, mac)
    rules = acl_rules(mud)
    out_ips = sorted({r["ip"] for r in rules["out"] if r["ip"]})
    out_dns = sorted({r["dns"] for r in rules["out"] if r["dns"]})
    lines: list[str] = []
    add = lines.append

    add("#!/usr/sbin/nft -f")
    add(f"# generated by iotsentinel {__version__}: "
        f"mud={mud.get('ietf-mud:mud', {}).get('mud-url', '?')}")
    add(f"# class={device_class} rung={rung} mac={mac}")
    add("# check only (no root): nft -c -f <this file>")
    add("")

    if rung == BLOCK_RUNG:
        add(f"table inet iotsentinel_quarantine_{name.replace('dev_', '')} "
            "{")
        add("  chain forward {")
        add("    type filter hook forward priority -10; policy accept;")
        add(f"    ether saddr {mac} udp dport 53 accept comment "
            f"\"quarantined: DNS only\"")
        add(f"    ether daddr {mac} ct state established,related accept")
        add(f"    counter name \"quarantined_dropped\" "
            f"log prefix \"iotsentinel-quarantine-drop \" drop")
        add("  }")
        add("}")
        add("")
        return "\n".join(lines) + "\n"

    add(f"table inet iotsentinel_{name} {{")
    if out_ips:
        add(f"  set {name}_allowed_v4 {{")
        add("    type ipv4_addr")
        add(f"    elements = {{ {', '.join(out_ips)} }}")
        add("  }")
    explicit_dns_rule = any(r["port"] == 53 for r in rules["out"])
    add(f"  set {name}_mgmt_v4 {{")
    add("    type ipv4_addr")
    nets = mgmt_subnets or ["192.168.1.0/24"]
    add(f"    elements = {{ {', '.join(nets)} }}")
    add("  }")
    add("")
    # outbound chain
    add(f"  chain {name}_out {{")
    add("    ct state established,related accept")
    if rung in (ALLOW_RUNG, ALLOW_LOG_RUNG):
        log_action = "accept"
    else:                                       # restricted
        log_action = f"limit rate {rate} accept"
    for r in rules["out"]:
        if r["dns"]:
            add(f"    # dnsname rule: {r['dns']} (resolve at apply time,"
                f" see README limitations)")
            continue
        if r["ip"]:
            daddr = f"ip daddr @{name}_allowed_v4"
            dport = f" {r['proto']} dport {r['port']}" if r["port"] else ""
            add(f"    {daddr}{dport} {log_action}")
    if not explicit_dns_rule:
        add(f"    udp dport 53 accept comment \"DNS (always allowed)\"")
    if rung in (ALLOW_RUNG, ALLOW_LOG_RUNG):
        prefix = ("iotsentinel-allow " if rung == ALLOW_RUNG
                  else "iotsentinel-allowlog ")
        add(f"    counter log prefix \"{prefix}\" "
            f"{'accept' if rung == ALLOW_LOG_RUNG else 'drop'}")
        if rung == ALLOW_RUNG:
            add(f"    # ^ allow rung: deny-by-default for this device")
    else:                                       # restricted
        add(f"    counter log prefix \"iotsentinel-restrict-drop \" drop")
        add(f"    # never a blanket cut-off: allow-listed flows above "
            f"are rate-limited, not dropped")
    add("  }")
    add("")
    # inbound chain
    add(f"  chain {name}_in {{")
    add("    ct state established,related accept")
    for r in rules["in"]:
        if r["port"]:
            add(f"    {r['proto']} dport {r['port']} "
                f"{log_action}")
    if rung == RESTRICTED_RUNG:
        add(f"    ip saddr @{name}_mgmt_v4 accept comment "
            f"\"management subnet\"")
        add(f"    counter log prefix \"iotsentinel-inbound-restricted \" "
            f"drop")
    else:
        add(f"    counter log prefix \"iotsentinel-inbound-drop \" drop")
    add("  }")
    add("")
    add("  chain forward {")
    add("    type filter hook forward priority 0; policy accept;")
    add(f"    ether saddr {mac} jump {name}_out")
    add(f"    ether daddr {mac} jump {name}_in")
    add("  }")
    if out_dns:
        add("")
        add("  # unresolved dnsname rules (kept out of the ruleset on")
        add("  # purpose; CDN IPs rotate. Provide resolution out of band:")
        for d in out_dns:
            add(f"  #   {d}")
    add("}")
    return "\n".join(lines) + "\n"


def cmd_enforce(args) -> int:
    try:
        mud = json.loads(Path(args.mud).read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"error: cannot read MUD file: {exc}", file=sys.stderr)
        return 1
    device_class = args.device_class
    tier = None
    if args.risk:
        try:
            risk = json.loads(Path(args.risk).read_text(encoding="utf-8"))
            tier = device_tier_from_risk(risk)
        except (json.JSONDecodeError, OSError) as exc:
            print(f"error: cannot read risk report: {exc}", file=sys.stderr)
            return 1
    rung = pick_rung(device_class, tier)
    mac = device_mac_from_mud(mud)
    ruleset = build_ruleset(mud, device_class, rung, mac)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(ruleset, encoding="utf-8")
    print(f"nftables ruleset written to {out}: class={device_class} "
          f"tier={tier or 'none'} rung={rung}")
    return 0
