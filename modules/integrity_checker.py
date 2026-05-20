import ipaddress

from modules.vlan_manager import load_vlans
from modules.device_manager import load_devices
from modules.firewall_manager import load_firewall_rules
from modules.switch_port_manager import load_switch_ports


def run_integrity_check():

    vlans = load_vlans()
    devices = load_devices()
    rules = load_firewall_rules()
    switch_ports = load_switch_ports()

    warnings = []

    vlan_lookup = {
        vlan["vlan_id"]: vlan
        for vlan in vlans
    }

    device_lookup = {
        device["hostname"].lower(): device
        for device in devices
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

            allowed_gateway_types = [
                "firewall",
                "router",
                "gateway"
            ]

            if device["device_type"].lower() not in allowed_gateway_types:
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
    # Switch Port Checks
    # -------------------------

    used_switch_ports = {}

    valid_switch_port_modes = [
        "access",
        "trunk",
        "unused"
    ]

    for port in switch_ports:

        switch_name = port["switch_name"]
        port_id = port["port_id"]
        mode = port["mode"]
        connected_device = port["connected_device"]

        port_key = (
            switch_name.lower(),
            port_id.lower()
        )

        if port_key not in used_switch_ports:
            used_switch_ports[port_key] = []

        used_switch_ports[port_key].append(
            f"{switch_name} port {port_id}"
        )

        if mode not in valid_switch_port_modes:
            warnings.append(
                f"[WARNING] Switch port {switch_name} port {port_id} "
                f"has invalid mode: {mode}"
            )
            continue

        if connected_device and connected_device.lower() not in [
            "none",
            "n/a",
            "spare",
            "unused"
        ]:
            if connected_device.lower() not in device_lookup:
                warnings.append(
                    f"[WARNING] Switch port {switch_name} port {port_id} "
                    f"references unknown device: {connected_device}"
                )

        if mode == "access":
            access_vlan = port["access_vlan"]

            if access_vlan not in vlan_lookup:
                warnings.append(
                    f"[WARNING] Switch port {switch_name} port {port_id} "
                    f"references missing access VLAN {access_vlan}"
                )

            if port["native_vlan"] is not None:
                warnings.append(
                    f"[WARNING] Access port {switch_name} port {port_id} "
                    f"should not have a native VLAN"
                )

            if port["allowed_vlans"]:
                warnings.append(
                    f"[WARNING] Access port {switch_name} port {port_id} "
                    f"should not have allowed VLANs"
                )

        elif mode == "trunk":
            native_vlan = port["native_vlan"]
            allowed_vlans = port["allowed_vlans"]

            if native_vlan not in vlan_lookup:
                warnings.append(
                    f"[WARNING] Trunk port {switch_name} port {port_id} "
                    f"references missing native VLAN {native_vlan}"
                )

            if not allowed_vlans:
                warnings.append(
                    f"[WARNING] Trunk port {switch_name} port {port_id} "
                    f"has no allowed VLANs"
                )

            for vlan_id in allowed_vlans:
                if vlan_id not in vlan_lookup:
                    warnings.append(
                        f"[WARNING] Trunk port {switch_name} port {port_id} "
                        f"references missing allowed VLAN {vlan_id}"
                    )

            if port["access_vlan"] is not None:
                warnings.append(
                    f"[WARNING] Trunk port {switch_name} port {port_id} "
                    f"should not have an access VLAN"
                )

        elif mode == "unused":
            assigned_vlan = port["assigned_vlan"]

            if assigned_vlan not in vlan_lookup:
                warnings.append(
                    f"[WARNING] Unused port {switch_name} port {port_id} "
                    f"references missing assigned VLAN {assigned_vlan}"
                )

            if port["access_vlan"] is not None:
                warnings.append(
                    f"[WARNING] Unused port {switch_name} port {port_id} "
                    f"should not have an access VLAN"
                )

            if port["native_vlan"] is not None:
                warnings.append(
                    f"[WARNING] Unused port {switch_name} port {port_id} "
                    f"should not have a native VLAN"
                )

            if port["allowed_vlans"]:
                warnings.append(
                    f"[WARNING] Unused port {switch_name} port {port_id} "
                    f"should not have allowed VLANs"
                )

    for port_key, port_entries in used_switch_ports.items():
        if len(port_entries) > 1:
            warnings.append(
                f"[WARNING] Duplicate switch port detected: "
                f"{', '.join(port_entries)}"
            )

    # -------------------------
    # Firewall Rule Checks
    # -------------------------

    valid_special_endpoints = ["internet", "any"]

    for rule in rules:
        source = rule["source_vlan"]
        destination = rule["destination_vlan"]

        if (
            source not in vlan_lookup
            and source not in valid_special_endpoints
        ):
            warnings.append(
                f"[WARNING] Firewall Rule "
                f"{rule['rule_id']} references "
                f"missing source VLAN "
                f"{source}"
            )

        if (
            destination not in vlan_lookup
            and destination not in valid_special_endpoints
        ):
            warnings.append(
                f"[WARNING] Firewall Rule "
                f"{rule['rule_id']} references "
                f"missing destination VLAN "
                f"{destination}"
            )

        if source == destination:
            warnings.append(
                f"[WARNING] Firewall Rule "
                f"{rule['rule_id']} has identical "
                f"source/destination endpoints"
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