import json
from pathlib import Path


DATA_FILE = Path("data/firewall_rules.json")


def load_firewall_rules():
    try:
        with open(DATA_FILE, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return []
    except json.JSONDecodeError:
        print("Error: firewall_rules.json is not valid JSON.")
        return []


def save_firewall_rules(rules):
    with open(DATA_FILE, "w") as file:
        json.dump(rules, file, indent=4)


def get_next_rule_id(rules):
    if not rules:
        return 1

    highest_id = max(rule["rule_id"] for rule in rules)
    return highest_id + 1


def add_firewall_rule(source_vlan, destination_vlan, protocol, port, action, purpose):
    rules = load_firewall_rules()

    new_rule = {
        "rule_id": get_next_rule_id(rules),
        "source_vlan": source_vlan,
        "destination_vlan": destination_vlan,
        "protocol": protocol.upper(),
        "port": port,
        "action": action.lower(),
        "purpose": purpose
    }

    rules.append(new_rule)
    save_firewall_rules(rules)

    print(f"Firewall rule {new_rule['rule_id']} added successfully.")


def list_firewall_rules():
    rules = load_firewall_rules()

    if not rules:
        print("No firewall rules found.")
        return

    print("\nCurrent Firewall Rules")
    print("-" * 40)

    for rule in rules:
        print(f"Rule ID: {rule['rule_id']}")
        print(f"Source VLAN: {rule['source_vlan']}")
        print(f"Destination VLAN: {rule['destination_vlan']}")
        print(f"Protocol: {rule['protocol']}")
        print(f"Port: {rule['port']}")
        print(f"Action: {rule['action']}")
        print(f"Purpose: {rule['purpose']}")
        print("-" * 40)


def delete_firewall_rule(rule_id):
    rules = load_firewall_rules()

    updated_rules = [
        rule for rule in rules
        if rule["rule_id"] != rule_id
    ]

    if len(updated_rules) == len(rules):
        print(f"Error: Firewall rule {rule_id} was not found.")
        return

    save_firewall_rules(updated_rules)
    print(f"Firewall rule {rule_id} deleted successfully.")


def edit_firewall_rule(rule_id, updated_rule):
    rules = load_firewall_rules()

    for index, rule in enumerate(rules):
        if rule["rule_id"] == rule_id:
            rules[index] = updated_rule
            save_firewall_rules(rules)
            print(f"Firewall rule {rule_id} updated successfully.")
            return

    print(f"Error: Firewall rule {rule_id} was not found.")


def firewall_rule_exists(source_vlan, destination_vlan, protocol, port, action, ignore_rule_id=None):
    rules = load_firewall_rules()

    for rule in rules:
        if ignore_rule_id is not None and rule["rule_id"] == ignore_rule_id:
            continue

        if (
            rule["source_vlan"] == source_vlan
            and rule["destination_vlan"] == destination_vlan
            and rule["protocol"].upper() == protocol.upper()
            and str(rule["port"]).lower() == str(port).lower()
            and rule["action"].lower() == action.lower()
        ):
            return True

    return False


def load_firewall_rules():
    try:
        with open(DATA_FILE, "r") as file:
            return json.load(file)

    except FileNotFoundError:
        print("Warning: firewall_rules.json not found. Returning empty firewall rule list.")
        return []

    except json.JSONDecodeError:
        print("Error: firewall_rules.json contains invalid JSON.")
        print("Fix the file before continuing.")
        return []

