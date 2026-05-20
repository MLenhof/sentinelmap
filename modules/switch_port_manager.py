import json
from pathlib import Path


DATA_FILE = Path("data/switch_ports.json")


def load_switch_ports():
    try:
        with open(DATA_FILE, "r") as file:
            return json.load(file)

    except FileNotFoundError:
        print("Warning: switch_ports.json not found. Returning empty switch port list.")
        return []

    except json.JSONDecodeError:
        print("Error: switch_ports.json contains invalid JSON.")
        print("Fix the file before continuing.")
        return []


def save_switch_ports(switch_ports):
    with open(DATA_FILE, "w") as file:
        json.dump(switch_ports, file, indent=4)


def switch_port_exists(switch_name, port_id):
    switch_ports = load_switch_ports()

    for switch_port in switch_ports:
        if (
            switch_port["switch_name"].lower() == switch_name.lower()
            and switch_port["port_id"].lower() == port_id.lower()
        ):
            return True

    return False


def add_switch_port(
    switch_name,
    port_id,
    description,
    mode,
    connected_device,
    poe_enabled,
    access_vlan,
    native_vlan,
    allowed_vlans,
    assigned_vlan,
    notes
):
    switch_ports = load_switch_ports()

    if switch_port_exists(switch_name, port_id):
        print(f"Error: Port {port_id} on switch '{switch_name}' already exists.")
        return

    new_switch_port = {
        "switch_name": switch_name,
        "port_id": port_id,
        "description": description,
        "mode": mode,
        "connected_device": connected_device,
        "poe_enabled": poe_enabled,
        "access_vlan": access_vlan,
        "native_vlan": native_vlan,
        "allowed_vlans": allowed_vlans,
        "assigned_vlan": assigned_vlan,
        "notes": notes
    }

    switch_ports.append(new_switch_port)
    save_switch_ports(switch_ports)

    print(f"Switch port {switch_name} port {port_id} added successfully.")


def list_switch_ports():
    switch_ports = load_switch_ports()

    if not switch_ports:
        print("No switch ports found.")
        return

    print("\nCurrent Switch Ports")
    print("-" * 40)

    for switch_port in switch_ports:
        print(f"Switch: {switch_port['switch_name']}")
        print(f"Port: {switch_port['port_id']}")
        print(f"Description: {switch_port['description']}")
        print(f"Mode: {switch_port['mode']}")
        print(f"Connected Device: {switch_port['connected_device']}")
        print(f"PoE Enabled: {switch_port['poe_enabled']}")

        if switch_port["mode"] == "access":
            print(f"Access VLAN: {switch_port['access_vlan']}")

        elif switch_port["mode"] == "trunk":
            print(f"Native VLAN: {switch_port['native_vlan']}")
            print(f"Allowed VLANs: {switch_port['allowed_vlans']}")

        elif switch_port["mode"] == "unused":
            print(f"Assigned VLAN: {switch_port['assigned_vlan']}")

        print(f"Notes: {switch_port['notes']}")
        print("-" * 40)


def edit_switch_port(switch_name, port_id, updated_switch_port):
    switch_ports = load_switch_ports()

    for index, switch_port in enumerate(switch_ports):
        if (
            switch_port["switch_name"].lower() == switch_name.lower()
            and switch_port["port_id"].lower() == port_id.lower()
        ):
            switch_ports[index] = updated_switch_port
            save_switch_ports(switch_ports)
            print(f"Switch port {switch_name} port {port_id} updated successfully.")
            return

    print(f"Error: Port {port_id} on switch '{switch_name}' was not found.")


def delete_switch_port(switch_name, port_id):
    switch_ports = load_switch_ports()

    updated_switch_ports = [
        switch_port for switch_port in switch_ports
        if not (
            switch_port["switch_name"].lower() == switch_name.lower()
            and switch_port["port_id"].lower() == port_id.lower()
        )
    ]

    if len(updated_switch_ports) == len(switch_ports):
        print(f"Error: Port {port_id} on switch '{switch_name}' was not found.")
        return

    save_switch_ports(updated_switch_ports)
    print(f"Switch port {switch_name} port {port_id} deleted successfully.")
