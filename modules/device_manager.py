import json
from pathlib import Path


DATA_FILE = Path("data/devices.json")


def load_devices():
    try:
        with open(DATA_FILE, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return []
    except json.JSONDecodeError:
        print("Error: devices.json is not valid JSON.")
        return []


def save_devices(devices):
    with open(DATA_FILE, "w") as file:
        json.dump(devices, file, indent=4)


def add_device(hostname, device_type, ip_address, vlan_id, location, role, notes):
    devices = load_devices()

    # Prevent duplicate hostnames
    for device in devices:
        if device["hostname"].lower() == hostname.lower():
            print(f"Error: Device '{hostname}' already exists.")
            return

    new_device = {
        "hostname": hostname,
        "device_type": device_type,
        "ip_address": ip_address,
        "vlan_id": vlan_id,
        "location": location,
        "role": role,
        "notes": notes
    }

    devices.append(new_device)
    save_devices(devices)

    print(f"Device '{hostname}' added successfully.")


def list_devices():
    devices = load_devices()

    if not devices:
        print("No devices found.")
        return

    print("\nCurrent Devices")
    print("-" * 40)

    for device in devices:
        print(f"Hostname: {device['hostname']}")
        print(f"Type: {device['device_type']}")
        print(f"IP Address: {device['ip_address']}")
        print(f"VLAN ID: {device['vlan_id']}")
        print(f"Location: {device['location']}")
        print(f"Role: {device['role']}")
        print(f"Notes: {device['notes']}")
        print("-" * 40)


def delete_device(hostname):
    devices = load_devices()

    updated_devices = [
        device for device in devices
        if device["hostname"].lower() != hostname.lower()
    ]

    if len(updated_devices) == len(devices):
        print(f"Error: Device '{hostname}' was not found.")
        return

    save_devices(updated_devices)
    print(f"Device '{hostname}' deleted successfully.")


def edit_device(hostname, updated_device):
    devices = load_devices()

    for index, device in enumerate(devices):
        if device["hostname"].lower() == hostname.lower():
            devices[index] = updated_device
            save_devices(devices)
            print(f"Device '{hostname}' updated successfully.")
            return

    print(f"Error: Device '{hostname}' was not found.")


def load_devices():
    try:
        with open(DATA_FILE, "r") as file:
            return json.load(file)

    except FileNotFoundError:
        print("Warning: devices.json not found. Returning empty device list.")
        return []

    except json.JSONDecodeError:
        print("Error: devices.json contains invalid JSON.")
        print("Fix the file before continuing.")
        return []

