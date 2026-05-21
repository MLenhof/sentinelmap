from modules.vlan_manager import load_vlans
from modules.firewall_manager import load_firewall_rules


def normalize_endpoint(endpoint):
    endpoint = str(endpoint).strip().lower()

    if endpoint in ["internet", "any"]:
        return endpoint

    try:
        return int(endpoint)

    except ValueError:
        return None

def find_vlan_by_id(vlan_id):
    vlans = load_vlans()

    for vlan in vlans:
        if vlan["vlan_id"] == vlan_id:
            return vlan

    return None


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