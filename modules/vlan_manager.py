import json
from pathlib import Path


# This builds the path to the vlans.json file.
# pathlib helps make paths work better across different systems.
DATA_FILE = Path("data/vlans.json")


def load_vlans():
    """
    Load VLAN data from the JSON file.

    Returns:
        list: A list of VLAN dictionaries.
    """
    try:
        with open(DATA_FILE, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return []
    except json.JSONDecodeError:
        print("Error: vlans.json is not valid JSON.")
        return []


def save_vlans(vlans):
    """
    Save VLAN data back to the JSON file.

    Args:
        vlans (list): A list of VLAN dictionaries.
    """
    with open(DATA_FILE, "w") as file:
        json.dump(vlans, file, indent=4)


def add_vlan(vlan_id, name, subnet, gateway, purpose, security_notes):
    """
    Add a new VLAN to vlans.json.

    Args:
        vlan_id (int): VLAN number.
        name (str): VLAN name.
        subnet (str): Subnet in CIDR format.
        gateway (str): Default gateway.
        purpose (str): Why this VLAN exists.
        security_notes (str): Security considerations.
    """
    vlans = load_vlans()

    if vlan_id < 1 or vlan_id > 4094:
        print("Error: VLAN ID must be between 1 and 4094.")
        return

    # Prevent duplicate VLAN IDs
    for vlan in vlans:
        if vlan["vlan_id"] == vlan_id:
            print(f"Error: VLAN {vlan_id} already exists.")
            return

    new_vlan = {
        "vlan_id": vlan_id,
        "name": name,
        "subnet": subnet,
        "gateway": gateway,
        "purpose": purpose,
        "security_notes": security_notes
    }

    vlans.append(new_vlan)
    save_vlans(vlans)

    print(f"VLAN {vlan_id} - {name} added successfully.")


def list_vlans():
    """
    Display all VLANs currently stored in vlans.json.
    """
    vlans = load_vlans()

    if not vlans:
        print("No VLANs found.")
        return

    print("\nCurrent VLANs")
    print("-" * 40)

    for vlan in vlans:
        print(f"VLAN ID: {vlan['vlan_id']}")
        print(f"Name: {vlan['name']}")
        print(f"Subnet: {vlan['subnet']}")
        print(f"Gateway: {vlan['gateway']}")
        print(f"Purpose: {vlan['purpose']}")
        print(f"Security Notes: {vlan['security_notes']}")
        print("-" * 40)


def list_vlan_summary():
    """
    Display a short summary of available VLANs.
    """

    vlans = load_vlans()

    if not vlans:
        print("No VLANs available.")
        return

    print("\nAvailable VLANs")
    print("-" * 30)

    for vlan in vlans:
        print(f"{vlan['vlan_id']} - {vlan['name']}")

    print("-" * 30)


def vlan_exists(vlan_id):
    """
    Check whether a VLAN ID already exists.

    Args:
        vlan_id (int): VLAN number to check.

    Returns:
        bool: True if VLAN exists, False otherwise.
    """
    vlans = load_vlans()

    for vlan in vlans:
        if int(vlan["vlan_id"] == vlan_id):
            return True

    return False


def delete_vlan(vlan_id):
    vlans = load_vlans()

    updated_vlans = [
        vlan for vlan in vlans
        if vlan["vlan_id"] != vlan_id
    ]

    if len(updated_vlans) == len(vlans):
        print(f"Error: VLAN {vlan_id} was not found.")
        return

    save_vlans(updated_vlans)
    print(f"VLAN {vlan_id} deleted successfully.")

def edit_vlan(vlan_id, updated_vlan):
    vlans = load_vlans()

    for index, vlan in enumerate(vlans):
        if vlan["vlan_id"] == vlan_id:
            vlans[index] = updated_vlan
            save_vlans(vlans)
            print(f"VLAN {vlan_id} updated successfully.")
            return

    print(f"Error: VLAN {vlan_id} was not found.")

def load_vlans():
    try:
        with open(DATA_FILE, "r") as file:
            return json.load(file)

    except FileNotFoundError:
        print("Warning: vlans.json not found. Returning empty VLAN list.")
        return []

    except json.JSONDecodeError:
        print("Error: vlans.json contains invalid JSON.")
        print("Fix the file before continuing.")
        return []


