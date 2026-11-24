#!/usr/bin/env python3
"""
Interactive Linux Multi-Tenant & Secure App Network Lab Generator
Generates organized iproute2 / iptables (with nftables fallback) scripts.
"""

import json
import os
from dataclasses import dataclass, field, asdict
from typing import List


@dataclass
class HostNode:
    name: str
    ip_cidr: str
    gateway: str
    veth_host: str
    veth_br: str


@dataclass
class NetworkSegment:
    name: str
    bridge_name: str
    subnet_cidr: str
    gateway_ip: str
    rtr_veth_rtr: str
    rtr_veth_br: str
    hosts: List[HostNode] = field(default_factory=list)


@dataclass
class TenantLab:
    lab_name: str
    router_ns: str = "rtr-core"
    segments: List[NetworkSegment] = field(default_factory=list)
    allow_inter_segment_same_tenant: bool = False


def get_valid_int(prompt: str, min_val: int = 1, max_val: int = 10) -> int:
    while True:
        raw = input(prompt).strip()
        if raw.isdigit() and min_val <= int(raw) <= max_val:
            return int(raw)
        print(f"  [!] Enter a number between {min_val} and {max_val}.")


def sanitize_ifname(name: str, max_len: int = 15) -> str:
    """Linux kernel IFNAMSIZ limit is 15 characters (+ null terminator)."""
    return name[:max_len]


def design_lab_interactive() -> TenantLab:
    print("\n" + "=" * 65)
    print("  LINUX NETWORKING LAB ARCHITECT (veth / bridges / netns)")
    print("=" * 65)

    lab_name = input("1. Enter Lab Name [default: multitenant-sec-lab]: ").strip() or "multitenant-sec-lab"
    lab = TenantLab(lab_name=lab_name)

    print("\n--- Architecture Mode ---")
    print("  [1] Multi-Tenant Client Isolation (Separate client networks, zero cross-talk)")
    print("  [2] Secure 3-Tier Application (Web -> App -> DB segmented zones)")
    print("  [3] Custom Hybrid Topology")
    mode = get_valid_int("Select topology template (1-3): ", 1, 3)

    if mode == 1:
        num_tenants = get_valid_int("How many isolated client tenants to create? (2-5): ", 2, 5)
        for t_idx in range(1, num_tenants + 1):
            t_id = f"t{t_idx}"
            br_name = sanitize_ifname(f"br-{t_id}")
            subnet = f"10.{t_idx}.10.0/24"
            gw_ip = f"10.{t_idx}.10.1"
            seg = NetworkSegment(
                name=f"tenant-{t_idx}",
                bridge_name=br_name,
                subnet_cidr=subnet,
                gateway_ip=gw_ip,
                rtr_veth_rtr=sanitize_ifname(f"v-rtr-{t_id}"),
                rtr_veth_br=sanitize_ifname(f"v-br-{t_id}"),
            )
            num_hosts = get_valid_int(f"  Number of endpoints in Tenant {t_idx} (1-4): ", 1, 4)
            for h_idx in range(1, num_hosts + 1):
                h_name = f"{t_id}-host{h_idx}"
                seg.hosts.append(
                    HostNode(
                        name=h_name,
                        ip_cidr=f"10.{t_idx}.10.{10 + h_idx}/24",
                        gateway=gw_ip,
                        veth_host=sanitize_ifname(f"v-{t_id}h{h_idx}"),
                        veth_br=sanitize_ifname(f"vb-{t_id}h{h_idx}"),
                    )
                )
            lab.segments.append(seg)

    elif mode == 2:
        tiers = [
            ("web", "10.100.1.0/24", "10.100.1.1", 2),
            ("app", "10.100.2.0/24", "10.100.2.1", 2),
            ("db",  "10.100.3.0/24", "10.100.3.1", 1),
        ]
        print("  [+] Building 3-Tier Secure App: Web (10.100.1.0/24), App (10.100.2.0/24), DB (10.100.3.0/24)")
        for idx, (tier_name, subnet, gw_ip, count) in enumerate(tiers, start=1):
            seg = NetworkSegment(
                name=f"tier-{tier_name}",
                bridge_name=sanitize_ifname(f"br-{tier_name}"),
                subnet_cidr=subnet,
                gateway_ip=gw_ip,
                rtr_veth_rtr=sanitize_ifname(f"v-rtr-{tier_name}"),
                rtr_veth_br=sanitize_ifname(f"v-br-{tier_name}"),
            )
            for h_idx in range(1, count + 1):
                h_name = f"{tier_name}-srv{h_idx}"
                seg.hosts.append(
                    HostNode(
                        name=h_name,
                        ip_cidr=f"10.100.{idx}.{10 + h_idx}/24",
                        gateway=gw_ip,
                        veth_host=sanitize_ifname(f"v-{tier_name[:3]}{h_idx}"),
                        veth_br=sanitize_ifname(f"vb-{tier_name[:3]}{h_idx}"),
                    )
                )
            lab.segments.append(seg)
        lab.allow_inter_segment_same_tenant = True

    else:
        num_segs = get_valid_int("How many network segments/bridges to create? (1-6): ", 1, 6)
        for s_idx in range(1, num_segs + 1):
            seg_label = input(f"  Segment {s_idx} short name (e.g., clientA, dmz, prod): ").strip() or f"seg{s_idx}"
            seg_label = "".join(c for c in seg_label if c.isalnum())[:6]
            subnet = f"172.16.{s_idx}.0/24"
            gw_ip = f"172.16.{s_idx}.1"
            seg = NetworkSegment(
                name=seg_label,
                bridge_name=sanitize_ifname(f"br-{seg_label}"),
                subnet_cidr=subnet,
                gateway_ip=gw_ip,
                rtr_veth_rtr=sanitize_ifname(f"v-rtr-{seg_label}"),
                rtr_veth_br=sanitize_ifname(f"v-br-{seg_label}"),
            )
            num_hosts = get_valid_int(f"    How many namespaces in '{seg_label}'? (1-4): ", 1, 4)
            for h_idx in range(1, num_hosts + 1):
                seg.hosts.append(
                    HostNode(
                        name=f"{seg_label}-ns{h_idx}",
                        ip_cidr=f"172.16.{s_idx}.{10 + h_idx}/24",
                        gateway=gw_ip,
                        veth_host=sanitize_ifname(f"v-{seg_label[:4]}{h_idx}"),
                        veth_br=sanitize_ifname(f"vb-{seg_label[:4]}{h_idx}"),
                    )
                )
            lab.segments.append(seg)
        iso = input("Allow routed traffic between these segments? (y/N): ").strip().lower()
        lab.allow_inter_segment_same_tenant = iso == "y"

    return lab


def generate_scripts(lab: TenantLab) -> tuple[str, str, str]:
    deploy: List[str] = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        f"# Lab: {lab.lab_name}",
        "# Generated by NetLab-Architect Python CLI\n",
        "# Clean up any leftover lab state before building",
        f"ip netns del {lab.router_ns} 2>/dev/null || true",
    ]

    teardown: List[str] = [
        "#!/usr/bin/env bash",
        f"# Teardown Script for Lab: {lab.lab_name}",
        f"echo '[*] Removing central router namespace {lab.router_ns}...'",
        f"ip netns del {lab.router_ns} 2>/dev/null || true",
    ]

    verify: List[str] = [
        f"# === VERIFICATION COMMANDS FOR {lab.lab_name.upper()} ===",
        "# 1. Inspect namespaces and bridges:",
        "ip netns list",
        "bridge link show\n",
        "# 2. Check routing table inside central router:",
        f"ip netns exec {lab.router_ns} ip route show\n",
    ]

    for seg in lab.segments:
        deploy.extend([
            f"ip link del {seg.rtr_veth_br} 2>/dev/null || true",
            f"ip link del {seg.bridge_name} 2>/dev/null || true",
        ])
        teardown.extend([
            f"ip link del {seg.rtr_veth_br} 2>/dev/null || true",
            f"ip link set {seg.bridge_name} down 2>/dev/null || true",
            f"ip link del {seg.bridge_name} 2>/dev/null || true",
        ])

    for seg in lab.segments:
        for host in seg.hosts:
            deploy.append(f"ip netns del {host.name} 2>/dev/null || true")
            teardown.append(f"ip netns del {host.name} 2>/dev/null || true")

    deploy.extend([
        "\necho '[1/5] Creating central router namespace and enabling IPv4 forwarding...'",
        f"ip netns add {lab.router_ns}",
        f"ip netns exec {lab.router_ns} ip link set lo up",
        f"ip netns exec {lab.router_ns} sysctl -w net.ipv4.ip_forward=1 >/dev/null\n",
        "echo '[2/5] Creating Layer-2 Bridges and Uplink veth pairs to Router...'",
    ])

    for seg in lab.segments:
        deploy.extend([
            f"# --- Segment: {seg.name} ({seg.subnet_cidr}) ---",
            f"ip link add name {seg.bridge_name} type bridge",
            f"ip link set {seg.bridge_name} up",
            f"ip link add {seg.rtr_veth_rtr} type veth peer name {seg.rtr_veth_br}",
            f"ip link set {seg.rtr_veth_rtr} netns {lab.router_ns}",
            f"ip link set {seg.rtr_veth_br} master {seg.bridge_name}",
            f"ip link set {seg.rtr_veth_br} up",
            f"ip netns exec {lab.router_ns} ip addr add {seg.gateway_ip}/24 dev {seg.rtr_veth_rtr}",
            f"ip netns exec {lab.router_ns} ip link set {seg.rtr_veth_rtr} up\n",
        ])

    deploy.append("echo '[3/5] Creating Tenant/App Namespaces and attaching veth pairs...'")
    for seg in lab.segments:
        for host in seg.hosts:
            deploy.extend([
                f"ip netns add {host.name}",
                f"ip netns exec {host.name} ip link set lo up",
                f"ip link add {host.veth_host} type veth peer name {host.veth_br}",
                f"ip link set {host.veth_host} netns {host.name}",
                f"ip link set {host.veth_br} master {seg.bridge_name}",
                f"ip link set {host.veth_br} up",
                f"ip netns exec {host.name} ip addr add {host.ip_cidr} dev {host.veth_host}",
                f"ip netns exec {host.name} ip link set {host.veth_host} up",
                f"ip netns exec {host.name} ip route add default via {host.gateway}\n",
            ])

    deploy.extend([
        "echo '[4/5] Applying Security & Isolation Policies inside Router Namespace...'",
        f"if ip netns exec {lab.router_ns} command -v iptables >/dev/null 2>&1; then",
        f"  ip netns exec {lab.router_ns} iptables -F FORWARD",
        f"  ip netns exec {lab.router_ns} iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
    ])

    if lab.allow_inter_segment_same_tenant and len(lab.segments) >= 2:
        deploy.append(f"  ip netns exec {lab.router_ns} iptables -P FORWARD DROP")
        for i in range(len(lab.segments) - 1):
            src = lab.segments[i].subnet_cidr
            dst = lab.segments[i + 1].subnet_cidr
            deploy.append(f"  ip netns exec {lab.router_ns} iptables -A FORWARD -s {src} -d {dst} -j ACCEPT")
    else:
        deploy.append(f"  ip netns exec {lab.router_ns} iptables -P FORWARD DROP")

    deploy.extend([
        f"elif ip netns exec {lab.router_ns} command -v nft >/dev/null 2>&1; then",
        f"  ip netns exec {lab.router_ns} nft add table inet filter",
        f"  ip netns exec {lab.router_ns} nft 'add chain inet filter forward {{ type filter hook forward priority 0; policy drop; }}'",
        f"  ip netns exec {lab.router_ns} nft add rule inet filter forward ct state established,related accept",
    ])

    if lab.allow_inter_segment_same_tenant and len(lab.segments) >= 2:
        for i in range(len(lab.segments) - 1):
            src = lab.segments[i].subnet_cidr
            dst = lab.segments[i + 1].subnet_cidr
            deploy.append(f"  ip netns exec {lab.router_ns} nft add rule inet filter forward ip saddr {src} ip daddr {dst} accept")

    deploy.extend([
        "else",
        "  echo '[!] WARNING: Neither iptables nor nft found. Install with: sudo apt install -y iptables nftables'",
        "fi",
        "\necho '[5/5] Lab deployment complete!'",
    ])
    teardown.append("echo '[*] Teardown complete. Host network state restored.'")

    if lab.segments and lab.segments[0].hosts:
        first_host = lab.segments[0].hosts[0]
        verify.append(f"# 3. Test gateway reachability from {first_host.name}:")
        verify.append(f"ip netns exec {first_host.name} ping -c 2 {first_host.gateway}\n")

        if len(lab.segments) >= 2 and lab.segments[1].hosts:
            second_host_ip = lab.segments[1].hosts[0].ip_cidr.split("/")[0]
            expectation = "SUCCEED (0% loss)" if lab.allow_inter_segment_same_tenant else "FAIL (100% packet loss - Tenant Isolation)"
            verify.append(f"# 4. Test cross-segment isolation ({first_host.name} -> {lab.segments[1].hosts[0].name}):")
            verify.append(f"#    Expected Result: {expectation}")
            verify.append(f"ip netns exec {first_host.name} ping -c 2 -W 1 {second_host_ip}\n")

    return "\n".join(deploy), "\n".join(verify), "\n".join(teardown)


def print_topology_map(lab: TenantLab) -> None:
    print("\n" + "=" * 65)
    print(f"  TOPOLOGY BLUEPRINT: {lab.lab_name}")
    print("=" * 65)
    print(f"  [Central Router NS: {lab.router_ns}] (FORWARD policy: DROP)")
    for seg in lab.segments:
        print(f"    ├── ({seg.rtr_veth_rtr}: {seg.gateway_ip}/24) <---> ({seg.rtr_veth_br}) [{seg.bridge_name}] ({seg.name})")
        for h in seg.hosts:
            print(f"    │      └── ({h.veth_br}) <---> ({h.veth_host}: {h.ip_cidr}) [NS: {h.name}]")
    print("=" * 65)


def main() -> None:
    lab = design_lab_interactive()
    print_topology_map(lab)

    deploy_sh, verify_txt, teardown_sh = generate_scripts(lab)

    out_dir = os.path.join(os.getcwd(), f"lab_{lab.lab_name}")
    os.makedirs(out_dir, exist_ok=True)

    deploy_path = os.path.join(out_dir, "deploy_lab.sh")
    teardown_path = os.path.join(out_dir, "teardown_lab.sh")
    verify_path = os.path.join(out_dir, "verify_commands.txt")
    manifest_path = os.path.join(out_dir, "topology.json")

    with open(deploy_path, "w", encoding="utf-8") as f:
        f.write(deploy_sh + "\n")
    os.chmod(deploy_path, 0o755)

    with open(teardown_path, "w", encoding="utf-8") as f:
        f.write(teardown_sh + "\n")
    os.chmod(teardown_path, 0o755)

    with open(verify_path, "w", encoding="utf-8") as f:
        f.write(verify_txt + "\n")

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(asdict(lab), f, indent=2)

    print("\n--- GENERATED DEPLOYMENT COMMANDS PREVIEW ---")
    print(deploy_sh)
    print("\n--- VERIFICATION COMMANDS ---")
    print(verify_txt)
    print(f"\n[+] All organized lab artifacts saved to: {out_dir}/")
    print("    - deploy_lab.sh      (Run with: sudo ./deploy_lab.sh)")
    print("    - verify_commands.txt (Copy/paste validation commands)")
    print("    - teardown_lab.sh    (Run with: sudo ./teardown_lab.sh)")
    print("    - topology.json      (Structured lab documentation)")


if __name__ == "__main__":
    main()
