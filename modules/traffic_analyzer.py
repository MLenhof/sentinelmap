from modules.vlan_manager import load_vlans
from modules.firewall_manager import load_firewall_rules


def get_vlan_name(vlans, vlan_id):
    if vlan_id in ["internet", "any"]:
        return vlan_id
    
    for vlan in vlans:
        if vlan["vlan_id"] == vlan_id:
            return vlan["name"]

    return "Unknown"


def show_traffic_summary():
    vlans = load_vlans()
    rules = load_firewall_rules()

    if not vlans:
        print("No VLANs found.")
        return

    print("\nTraffic Summary")
    print("-" * 40)

    for vlan in vlans:
        source_vlan = vlan["vlan_id"]
        source_name = vlan["name"]

        print(f"\nVLAN {source_vlan} - {source_name}")

        matching_rules = [
            rule for rule in rules
            if rule["source_vlan"] == source_vlan
        ]

        if not matching_rules:
            print("  No documented outbound firewall rules.")
            continue

        for rule in matching_rules:

            destination_name = get_vlan_name(
                vlans,
                rule["destination_vlan"]
            )

            print(
                f"  {rule['action'].upper()} → "
                f"VLAN {rule['destination_vlan']} "
                f"({destination_name}) "
                f"{rule['protocol']}/{rule['port']}"
            )

            print(f"    Why: {rule['purpose']}")