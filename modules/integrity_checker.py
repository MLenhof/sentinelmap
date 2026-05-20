import ipaddress

from modules.vlan_manager import load_vlans
from modules.device_manager import load_devices
from modules.firewall_manager import load_firewall_rules


def run_integrity_check():

    vlans = load_vlans()
    devices = load_devices()
    rules = load_firewall_rules()

    warnings = []

    vlan_lookup = {
        vlan["vlan_id"]: vlan
        for vlan in vlans
    }

    # -------------------------
    # VLAN Checks
    # -------------------------

    used_vlan_ids = {}
    used_subnets = {}
    used_gateways = {}

    for vlan in vlans:
        vlan_id = vlan["vlan_id"]
        subnet_value = vlan["subnet"]
        gateway_value = vlan["gateway"]

        # Track duplicate VLAN IDs
        if vlan_id not in used_vlan_ids:
            used_vlan_ids[vlan_id] = []

        used_vlan_ids[vlan_id].append(vlan["name"])

        # Validate subnet format
        try:
            subnet = ipaddress.ip_network(subnet_value, strict=False)
        except ValueError:
            warnings.append(
                f"[WARNING] VLAN {vlan_id} has invalid subnet: {subnet_value}"
            )
            continue

        # Track duplicate subnets
        subnet_key = str(subnet)

        if subnet_key not in used_subnets:
            used_subnets[subnet_key] = []

        used_subnets[subnet_key].append(vlan_id)

        # Validate gateway format
        try:
            gateway_ip = ipaddress.ip_address(gateway_value)
        except ValueError:
            warnings.append(
                f"[WARNING] VLAN {vlan_id} has invalid gateway: {gateway_value}"
            )
            continue

        # Gateway must be inside subnet
        if gateway_ip not in subnet:
            warnings.append(
                f"[WARNING] VLAN {vlan_id} gateway {gateway_value} "
                f"is outside subnet {subnet_value}"
            )

        # Gateway cannot be network address
        if gateway_ip == subnet.network_address:
            warnings.append(
                f"[WARNING] VLAN {vlan_id} gateway {gateway_value} "
                f"is the network address"
            )

        # Gateway cannot be broadcast address
        if gateway_ip == subnet.broadcast_address:
            warnings.append(
                f"[WARNING] VLAN {vlan_id} gateway {gateway_value} "
                f"is the broadcast address"
            )

        # Track duplicate gateways
        if gateway_value not in used_gateways:
            used_gateways[gateway_value] = []

        used_gateways[gateway_value].append(vlan_id)

    # Duplicate VLAN ID detection
    for vlan_id, vlan_names in used_vlan_ids.items():
        if len(vlan_names) > 1:
            warnings.append(
                f"[WARNING] Duplicate VLAN ID detected: "
                f"{vlan_id} used by {', '.join(vlan_names)}"
            )

    # Duplicate subnet detection
    for subnet, vlan_ids in used_subnets.items():
        if len(vlan_ids) > 1:
            warnings.append(
                f"[WARNING] Duplicate subnet detected: "
                f"{subnet} used by VLANs {vlan_ids}"
            )

    # Duplicate gateway detection
    for gateway, vlan_ids in used_gateways.items():
        if len(vlan_ids) > 1:
            warnings.append(
                f"[WARNING] Duplicate gateway detected: "
                f"{gateway} used by VLANs {vlan_ids}"
            )

    # -------------------------
    # Device Checks
    # -------------------------

    used_ips = {}
    used_hostnames = {}

    for device in devices:

        vlan_id = device["vlan_id"]

        # Check if VLAN exists
        if vlan_id not in vlan_lookup:
            warnings.append(
                f"[WARNING] Device '{device['hostname']}' "
                f"references missing VLAN {vlan_id}"
            )
            continue

        vlan = vlan_lookup[vlan_id]

        subnet = ipaddress.ip_network(
            vlan["subnet"],
            strict=False
        )

        device_ip = ipaddress.ip_address(
            device["ip_address"]
        )

        # Check if device IP is inside subnet
        if device_ip not in subnet:
            warnings.append(
                f"[WARNING] Device '{device['hostname']}' "
                f"IP {device_ip} is outside "
                f"VLAN {vlan_id} subnet {vlan['subnet']}"
            )

        # Check if device IP equals gateway
        if device["ip_address"] == vlan["gateway"]:
            warnings.append(
                f"[WARNING] Device '{device['hostname']}' "
                f"uses the VLAN gateway IP "
                f"{vlan['gateway']}"
            )

        # Check for duplicate IPs
        if device["ip_address"] not in used_ips:
            used_ips[device["ip_address"]] = []

        used_ips[device["ip_address"]].append(
            device["hostname"]
        )

        # Check for duplicate hostnames
        hostname_key = device["hostname"].lower()

        if hostname_key not in used_hostnames:
            used_hostnames[hostname_key] = []

        used_hostnames[hostname_key].append(device["hostname"])

    # Duplicate IP detection
    for ip, hostnames in used_ips.items():

        if len(hostnames) > 1:
            warnings.append(
                f"[WARNING] Duplicate IP detected: "
                f"{ip} used by {', '.join(hostnames)}"
            )

    # Duplicate hostname detection
    for hostname_key, hostnames in used_hostnames.items():

        if len(hostnames) > 1:
            warnings.append(
                f"[WARNING] Duplicate hostname detected: "
                f"{', '.join(hostnames)}"
            )

    # -------------------------
    # Firewall Rule Checks
    # -------------------------

    for rule in rules:

        if rule["source_vlan"] not in vlan_lookup:
            warnings.append(
                f"[WARNING] Firewall Rule "
                f"{rule['rule_id']} references "
                f"missing source VLAN "
                f"{rule['source_vlan']}"
            )

        if rule["destination_vlan"] not in vlan_lookup:
            warnings.append(
                f"[WARNING] Firewall Rule "
                f"{rule['rule_id']} references "
                f"missing destination VLAN "
                f"{rule['destination_vlan']}"
            )

        if rule["source_vlan"] == rule["destination_vlan"]:
            warnings.append(
                f"[WARNING] Firewall Rule "
                f"{rule['rule_id']} has identical "
                f"source/destination VLANs"
            )

    # -------------------------
    # Output Results
    # -------------------------

    print("\nData Integrity Report")
    print("-" * 40)

    if not warnings:
        print("[OK] No integrity issues detected.")
        return

    for warning in warnings:
        print(warning)