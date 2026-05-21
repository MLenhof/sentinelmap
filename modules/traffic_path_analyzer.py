from modules.vlan_manager import load_vlans
from modules.firewall_manager import load_firewall_rules
from modules.device_manager import load_devices


def normalize_endpoint(endpoint):
    endpoint = str(endpoint).strip().lower()

    if endpoint in ["internet", "any"]:
        return endpoint

    try:
        return int(endpoint)

    except ValueError:
        return None


def find_device_by_hostname(hostname):
    devices = load_devices()
    hostname = hostname.strip().lower()

    for device in devices:
        if device["hostname"].lower() == hostname:
            return device

    return None


def find_vlan_by_id(vlan_id):
    vlans = load_vlans()

    for vlan in vlans:
        if vlan["vlan_id"] == vlan_id:
            return vlan

    return None


def print_known_devices():
    devices = load_devices()

    print("\nKnown Devices")

    for device in devices:
        print(f"- {device['hostname']}")


def analyze_vlan_path(source_vlan_id, destination_vlan_id):
    source_vlan_id = normalize_endpoint(source_vlan_id)
    destination_vlan_id = normalize_endpoint(destination_vlan_id)
    vlans = load_vlans()
    firewall_rules = load_firewall_rules()

    source_vlan = find_vlan_by_id(source_vlan_id)
    destination_vlan = find_vlan_by_id(destination_vlan_id)

    if destination_vlan is None and destination_vlan_id not in ["internet", "any"]:
        return {
            "result": "ERROR",
            "reason": f"Source VLAN {source_vlan_id} does not exist.",
            "matching_rules": []
        }

    if destination_vlan is None and destination_vlan_id not in ["internet", "any"]:
        return {
            "result": "ERROR",
            "reason": f"Destination VLAN {destination_vlan_id} does not exist.",
            "matching_rules": []
        }

    if source_vlan_id == destination_vlan_id:
        return {
            "result": "ALLOWED",
            "reason": "Source and destination are on the same VLAN.",
            "matching_rules": []
        }

    matching_rules = []

    for rule in firewall_rules:
        if (
            rule["source_vlan"] == source_vlan_id
            and rule["destination_vlan"] == destination_vlan_id
        ):
            matching_rules.append(rule)

    if not matching_rules:
        return {
            "result": "DENIED",
            "reason": "No matching firewall rule found. Traffic is denied by default.",
            "matching_rules": []
        }

    broad_allow_rules = []
    broad_deny_rules = []
    specific_allow_rules = []
    specific_deny_rules = []

    for rule in matching_rules:
        action = rule["action"].lower()
        protocol = str(rule["protocol"]).lower()
        port = str(rule["port"]).lower()

        is_broad_rule = protocol == "any" and port == "any"

        if action == "allow" and is_broad_rule:
            broad_allow_rules.append(rule)

        elif action == "deny" and is_broad_rule:
            broad_deny_rules.append(rule)

        elif action == "allow":
            specific_allow_rules.append(rule)

        elif action == "deny":
            specific_deny_rules.append(rule)

    if broad_deny_rules:
        result = "DENIED"
        reason = "A broad deny rule exists for this VLAN path."

    elif broad_allow_rules:
        result = "ALLOWED"
        reason = "A broad allow rule exists for this VLAN path."

    elif specific_allow_rules:
        result = "PARTIALLY ALLOWED"
        reason = "Specific traffic is allowed, but no broad allow rule exists. Other traffic is denied by default."

    elif specific_deny_rules:
        result = "DENIED"
        reason = "Only specific deny rules exist. No allow rule exists for this VLAN path."

    else:
        result = "DENIED"
        reason = "No usable allow rule found. Traffic is denied by default."

    return {
        "result": result,
        "reason": reason,
        "matching_rules": matching_rules
    }

    return {
        "result": "DENIED",
        "reason": "No matching firewall rule found. Traffic is denied by default.",
        "matching_rules": []
    }


def print_vlan_path_analysis(source_vlan_id, destination_vlan_id):
    result = analyze_vlan_path(source_vlan_id, destination_vlan_id)

    source_vlan = find_vlan_by_id(source_vlan_id)
    destination_vlan = find_vlan_by_id(destination_vlan_id)

    print("\nTraffic Path Analysis")
    print("-" * 40)

    if source_vlan:
        print(f"Source VLAN: {source_vlan['vlan_id']} - {source_vlan['name']}")
    else:
        print(f"Source VLAN: {source_vlan_id}")

    if destination_vlan:
        print(f"Destination VLAN: {destination_vlan['vlan_id']} - {destination_vlan['name']}")
    else:
        print(f"Destination VLAN: {destination_vlan_id}")

    print(f"Result: {result['result']}")
    print(f"Reason: {result['reason']}")

    if result["matching_rules"]:
        print("\nMatching Rules")

        for rule in result["matching_rules"]:
            print(
                f"- {rule['protocol']} / {rule['port']} / "
                f"{rule['action']} / {rule['purpose']}"
            )


def analyze_device_path(source_hostname, destination_hostname):
    source_device = find_device_by_hostname(source_hostname)
    destination_device = find_device_by_hostname(destination_hostname)

    if source_device is None:
        return {
            "result": "ERROR",
            "reason": f"Source device '{source_hostname}' does not exist.",
            "source_device": None,
            "destination_device": destination_device,
            "vlan_result": None
        }

    if destination_device is None:
        return {
            "result": "ERROR",
            "reason": f"Destination device '{destination_hostname}' does not exist.",
            "source_device": source_device,
            "destination_device": None,
            "vlan_result": None
        }

    source_vlan_id = source_device["vlan_id"]
    destination_vlan_id = destination_device["vlan_id"]

    vlan_result = analyze_vlan_path(
        source_vlan_id,
        destination_vlan_id
    )

    return {
        "result": vlan_result["result"],
        "reason": vlan_result["reason"],
        "source_device": source_device,
        "destination_device": destination_device,
        "vlan_result": vlan_result
    }


def print_device_path_analysis(source_hostname, destination_hostname):
    result = analyze_device_path(
        source_hostname,
        destination_hostname
    )

    print("\nDevice-to-Device Traffic Analysis")
    print("-" * 40)

    if result["source_device"]:
        source_device = result["source_device"]
        source_vlan = find_vlan_by_id(source_device["vlan_id"])

        print(f"Source Device: {source_device['hostname']}")

        if source_vlan:
            print(
                f"Source VLAN: {source_vlan['vlan_id']} - "
                f"{source_vlan['name']}"
            )
        else:
            print(f"Source VLAN: {source_device['vlan_id']}")

    else:
        print(f"Source Device: {source_hostname}")

    if result["destination_device"]:
        destination_device = result["destination_device"]
        destination_vlan = find_vlan_by_id(destination_device["vlan_id"])

        print(f"Destination Device: {destination_device['hostname']}")

        if destination_vlan:
            print(
                f"Destination VLAN: {destination_vlan['vlan_id']} - "
                f"{destination_vlan['name']}"
            )
        else:
            print(f"Destination VLAN: {destination_device['vlan_id']}")

    else:
        print(f"Destination Device: {destination_hostname}")

    print(f"Result: {result['result']}")
    print(f"Reason: {result['reason']}")

    if result["vlan_result"]:
        matching_rules = result["vlan_result"]["matching_rules"]

        if matching_rules:
            print("\nMatching Rules")

            for rule in matching_rules:
                print(
                    f"- {rule['protocol']} / {rule['port']} / "
                    f"{rule['action']} / {rule['purpose']}"
                )


