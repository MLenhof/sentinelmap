from modules.vlan_manager import (
    add_vlan,
    list_vlans,
    vlan_exists,
    list_vlan_summary,
    load_vlans,
    delete_vlan,
    edit_vlan
)
from modules.device_manager import (
    add_device,
    list_devices,
    delete_device,
    load_devices,
    edit_device
)
from modules.firewall_manager import (
    add_firewall_rule,
    list_firewall_rules,
    delete_firewall_rule,
    load_firewall_rules,
    edit_firewall_rule,
    firewall_rule_exists
)
from modules.switch_port_manager import (
    add_switch_port,
    list_switch_ports,
    delete_switch_port,
    edit_switch_port,
    load_switch_ports
)
from modules.traffic_analyzer import show_traffic_summary
from modules.report_generator import generate_markdown_report
from modules.integrity_checker import run_integrity_check
from modules.traffic_path_analyzer import print_vlan_path_analysis
import ipaddress


# -------------------------
# Input helper functions
# -------------------------

def get_vlan_id():
    while True:
        try:
            vlan_id = int(input("VLAN ID: "))

            if vlan_id < 1 or vlan_id > 4094:
                print("VLAN ID must be between 1 and 4094.")
                continue

            return vlan_id

        except ValueError:
            print("Invalid VLAN ID. Please enter a number.")


def get_new_vlan_id():
    while True:
        vlan_id = get_vlan_id()

        if vlan_exists(vlan_id):
            print(f"VLAN {vlan_id} already exists.")
            print("Choose a different VLAN ID.")
            list_vlan_summary()
            continue

        return vlan_id


def get_existing_vlan_id():
    while True:
        vlan_id = get_vlan_id()

        if vlan_exists(vlan_id):
            return vlan_id

        print(f"VLAN {vlan_id} does not exist yet.")
        list_vlan_summary()
        print("A device should normally be assigned to a VLAN that is already documented.")
        print("Add the VLAN first, then add the device.")

        choice = input("Would you like to enter a different VLAN ID? (y/n): ").lower()

        if choice != "y":
            return None


def get_vlan_by_id(vlan_id):
    vlans = load_vlans()

    for vlan in vlans:
        if vlan["vlan_id"] == vlan_id:
            return vlan

    return None


def get_vlan_id_to_delete():
    vlans = load_vlans()
    devices = load_devices()
    rules = load_firewall_rules()

    if not vlans:
        print("No VLANs available to delete.")
        return None

    print("\nSelect a VLAN to delete")
    print("-" * 30)

    for index, vlan in enumerate(vlans, start=1):
        print(f"{index}. VLAN {vlan['vlan_id']} - {vlan['name']}")

    while True:
        try:
            user_input = input(
                "Enter VLAN number to delete "
                "(or Q to cancel): "
            ).lower()

            if user_input == "q":
                return None

            choice = int(user_input)

            if 1 <= choice <= len(vlans):
                selected_vlan_id = vlans[choice - 1]["vlan_id"]

                device_refs = [
                    device for device in devices
                    if device["vlan_id"] == selected_vlan_id
                ]

                rule_refs = [
                    rule for rule in rules
                    if rule["source_vlan"] == selected_vlan_id
                    or rule["destination_vlan"] == selected_vlan_id
                ]

                if device_refs or rule_refs:
                    print(f"\nCannot delete VLAN {selected_vlan_id}.")
                    print("It is still referenced by:")

                    if device_refs:
                        print(f"- {len(device_refs)} device(s)")

                    if rule_refs:
                        print(f"- {len(rule_refs)} firewall rule(s)")

                    print("Remove or update those references first.")
                    return None

                return selected_vlan_id

            print("Invalid selection. Choose a number from the list.")

        except ValueError:
            print("Invalid input. Please enter a number.")


def get_ip_address(prompt):
    while True:
        ip_input = input(prompt)

        try:
            ipaddress.ip_address(ip_input)
            return ip_input

        except ValueError:
            print("Invalid IP address. Example: 192.168.10.10")


def get_subnet():
    while True:
        subnet = input(
            "Subnet in CIDR format "
            "(example: 192.168.10.0/24): "
        )

        try:
            ipaddress.ip_network(subnet, strict=False)
            return subnet

        except ValueError:
            print("Invalid subnet. Example: 192.168.10.0/24")


def get_gateway_for_subnet(subnet_value):
    subnet = ipaddress.ip_network(subnet_value, strict=False)
    devices = load_devices()

    while True:
        gateway = get_ip_address(
            f"Gateway IP inside {subnet_value} "
            f"(example: {subnet.network_address + 1}): "
        )

        gateway_ip = ipaddress.ip_address(gateway)

        if gateway_ip not in subnet:
            print(f"Invalid gateway. {gateway} is not inside {subnet_value}.")
            continue

        if gateway_ip == subnet.network_address:
            print("Invalid gateway. That is the network address.")
            continue

        if gateway_ip == subnet.broadcast_address:
            print("Invalid gateway. That is the broadcast address.")
            continue

        gateway_already_used = False

        for device in devices:
            if device["ip_address"] == gateway:
                gateway_already_used = True
                break

        if gateway_already_used:
            print("Invalid gateway. That IP is already assigned to a device.")
            continue

        return gateway


def get_ip_address_for_vlan(vlan, device_type):
    subnet = ipaddress.ip_network(vlan["subnet"], strict=False)
    devices = load_devices()

    while True:
        ip_input = input(
            f"IP address for VLAN {vlan['vlan_id']} "
            f"({vlan['name']}) "
            f"[subnet: {vlan['subnet']}]: "
        )

        try:
            ip = ipaddress.ip_address(ip_input)

            if ip not in subnet:
                print(f"Invalid IP. {ip_input} is not inside {vlan['subnet']}.")
                continue

            if ip == subnet.network_address:
                print("Invalid IP. That is the network address.")
                continue

            if ip == subnet.broadcast_address:
                print("Invalid IP. That is the broadcast address.")
                continue

            if ip_input == vlan["gateway"]:

                allowed_gateway_types = [
                    "firewall",
                    "router",
                    "gateway"
                ]

                if device_type.lower() not in allowed_gateway_types:
                    print(
                        "Invalid IP. That address is already "
                        "used as the VLAN gateway."
                    )
                    continue

            ip_already_used = False

            for device in devices:
                if device["ip_address"] == ip_input:
                    ip_already_used = True
                    break

            if ip_already_used:
                print("Invalid IP. That address is already assigned to another device.")
                continue

            return ip_input

        except ValueError:
            print("Invalid IP address. Example: 192.168.10.10")


def get_hostname_to_delete():
    devices = load_devices()

    if not devices:
        print("No devices available to delete.")
        return None

    print("\nSelect a device to delete")
    print("-" * 30)

    for index, device in enumerate(devices, start=1):
        print(f"{index}. {device['hostname']} ({device['ip_address']})")

    while True:
        try:
            user_input = input(
                "Enter device number to delete "
                "(or Q to cancel): "
            ).lower()

            if user_input == "q":
                return None

            choice = int(user_input)

            if 1 <= choice <= len(devices):
                return devices[choice - 1]["hostname"]

            print("Invalid selection. Choose a number from the list.")

        except ValueError:
            print("Invalid input. Please enter a number.")


def get_protocol():
    valid_protocols = ["TCP", "UDP", "ICMP", "ANY"]

    while True:
        protocol = input("Protocol (TCP/UDP/ICMP/ANY): ").upper()

        if protocol in valid_protocols:
            return protocol

        print("Invalid protocol.")
        print(f"Valid options: {', '.join(valid_protocols)}")


def get_firewall_action():
    while True:
        action = input("Action (allow/deny): ").lower()

        if action in ["allow", "deny"]:
            return action

        print("Invalid action. Please enter 'allow' or 'deny'.")


def get_firewall_endpoint(label):
    while True:
        user_input = input(
            f"{label} VLAN ID, 'internet', or 'any': "
        ).lower()

        if user_input in ["internet", "any"]:
            return user_input

        try:
            vlan_id = int(user_input)

            if vlan_exists(vlan_id):
                return vlan_id

            print(f"VLAN {vlan_id} does not exist.")
            list_vlan_summary()

        except ValueError:
            print("Invalid input. Enter a VLAN ID, 'internet', or 'any'.")


def select_firewall_rule():
    rules = load_firewall_rules()

    if not rules:
        print("No firewall rules available.")
        return None

    print("\nSelect a firewall rule")
    print("-" * 40)

    for index, rule in enumerate(rules, start=1):
        print(
            f"{index}. Rule {rule['rule_id']}: "
            f"VLAN {rule['source_vlan']} → "
            f"VLAN {rule['destination_vlan']} "
            f"{rule['protocol']}/{rule['port']} "
            f"{rule['action']}"
        )

    while True:
        try:
            user_input = input(
                "Enter firewall rule number "
                "(or Q to cancel): "
            ).lower()

            if user_input == "q":
                return None

            choice = int(user_input)

            if 1 <= choice <= len(rules):
                return rules[choice - 1]

            print("Invalid selection. Choose a number from the list.")

        except ValueError:
            print("Invalid input. Please enter a number.")


def get_rule_id_to_delete():
    rules = load_firewall_rules()

    if not rules:
        print("No firewall rules available to delete.")
        return None

    print("\nSelect a firewall rule to delete")
    print("-" * 40)

    for index, rule in enumerate(rules, start=1):
        print(
            f"{index}. Rule {rule['rule_id']}: "
            f"VLAN {rule['source_vlan']} → "
            f"VLAN {rule['destination_vlan']} "
            f"{rule['protocol']}/{rule['port']} "
            f"{rule['action']}"
        )

    while True:
        try:
            user_input = input(
                "Enter firewall rule number to delete "
                "(or Q to cancel): "
            ).lower()

            if user_input == "q":
                return None

            choice = int(user_input)

            if 1 <= choice <= len(rules):
                return rules[choice - 1]["rule_id"]

            print("Invalid selection. Choose a number from the list.")

        except ValueError:
            print("Invalid input. Please enter a number.")


def select_device():
    devices = load_devices()

    if not devices:
        print("No devices available.")
        return None

    print("\nSelect a device")
    print("-" * 30)

    for index, device in enumerate(devices, start=1):
        print(f"{index}. {device['hostname']} ({device['ip_address']})")

    while True:
        try:
            user_input = input(
                "Enter device number "
                "(or Q to cancel): "
            ).lower()

            if user_input == "q":
                return None

            choice = int(user_input)

            if 1 <= choice <= len(devices):
                return devices[choice - 1]

            print("Invalid selection. Choose a number from the list.")

        except ValueError:
            print("Invalid input. Please enter a number.")


def select_vlan():
    vlans = load_vlans()

    if not vlans:
        print("No VLANs available.")
        return None

    print("\nSelect a VLAN")
    print("-" * 30)

    for index, vlan in enumerate(vlans, start=1):
        print(f"{index}. VLAN {vlan['vlan_id']} - {vlan['name']}")

    while True:
        try:
            user_input = input(
                "Enter VLAN number "
                "(or Q to cancel): "
            ).lower()

            if user_input == "q":
                return None

            choice = int(user_input)

            if 1 <= choice <= len(vlans):
                return vlans[choice - 1]

            print("Invalid selection. Choose a number from the list.")

        except ValueError:
            print("Invalid input. Please enter a number.")


def get_new_hostname():
    devices = load_devices()

    while True:
        hostname = input("Hostname (example: proxmox-01, pfsense-fw): ")

        hostname_exists = False

        for device in devices:
            if device["hostname"].lower() == hostname.lower():
                hostname_exists = True
                break

        if hostname_exists:
            print(f"Device '{hostname}' already exists.")
            print("Choose a different hostname.")
            continue

        return hostname


def get_switch_port_mode():
    valid_modes = ["access", "trunk", "unused"]

    while True:
        mode = input("Port mode (access/trunk/unused): ").lower()

        if mode in valid_modes:
            return mode

        print("Invalid mode.")
        print("Access = one VLAN only")
        print("Trunk = carries multiple VLANs")
        print("Unused = not currently connected, usually assigned to a safe parking VLAN")


def get_poe_enabled():
    while True:
        poe_input = input("PoE enabled? (y/n): ").lower()

        if poe_input == "y":
            return True

        if poe_input == "n":
            return False

        print("Invalid input. Please enter y or n.")


def get_allowed_vlans():
    while True:
        vlan_input = input("Allowed VLAN IDs, comma-separated (example: 10,20,30): ")
        vlan_ids = []
        invalid_input = False

        for value in vlan_input.split(","):
            value = value.strip()

            try:
                vlan_id = int(value)
            except ValueError:
                print(f"Invalid VLAN ID: {value}")
                invalid_input = True
                break

            if not vlan_exists(vlan_id):
                print(f"VLAN {vlan_id} does not exist.")
                list_vlan_summary()
                invalid_input = True
                break

            vlan_ids.append(vlan_id)

        if invalid_input:
            continue

        if not vlan_ids:
            print("At least one allowed VLAN is required for a trunk port.")
            continue

        return vlan_ids


def select_switch_port():
    switch_ports = load_switch_ports()

    if not switch_ports:
        print("No switch ports available.")
        return None

    print("\nSelect a switch port")
    print("-" * 40)

    for index, switch_port in enumerate(switch_ports, start=1):
        print(
            f"{index}. {switch_port['switch_name']} "
            f"port {switch_port['port_id']} "
            f"({switch_port['mode']}) - "
            f"{switch_port['description']}"
        )

    while True:
        try:
            user_input = input(
                "Enter switch port number "
                "(or Q to cancel): "
            ).lower()

            if user_input == "q":
                return None

            choice = int(user_input)

            if 1 <= choice <= len(switch_ports):
                return switch_ports[choice - 1]

            print("Invalid selection. Choose a number from the list.")

        except ValueError:
            print("Invalid input. Please enter a number.")


def get_switch_port_identity_to_delete():
    switch_port = select_switch_port()

    if switch_port is None:
        return None

    return switch_port["switch_name"], switch_port["port_id"]


# -------------------------
# Menu display functions
# -------------------------

def show_main_menu():
    print("\nSentinelMap")
    print("1. VLAN Management")
    print("2. Device Management")
    print("3. Firewall Rule Management")
    print("4. Switch Port Management")
    print("5. Traffic Analysis")
    print("6. Reports")
    print("7. Data Integrity Check")
    print("8. Traffic Path Analysis")
    print("9. Exit")


def show_vlan_menu():
    print("\nVLAN Management")
    print("1. Add VLAN")
    print("2. List VLANs")
    print("3. Edit VLAN")
    print("4. Delete VLAN")
    print("5. Back")


def show_device_menu():
    print("\nDevice Management")
    print("1. Add Device")
    print("2. List Devices")
    print("3. Edit Device")
    print("4. Delete Device")
    print("5. Back")


def show_firewall_menu():
    print("\nFirewall Rule Management")
    print("1. Add Firewall Rule")
    print("2. List Firewall Rules")
    print("3. Edit Firewall Rule")
    print("4. Delete Firewall Rule")
    print("5. Back")


def show_switch_port_menu():
    print("\nSwitch Port Management")
    print("1. Add Switch Port")
    print("2. List Switch Ports")
    print("3. Edit Switch Port")
    print("4. Delete Switch Port")
    print("5. Back")


def traffic_path_menu():
    while True:
        print("\nTraffic Path Analysis")
        print("1. Analyze VLAN-to-VLAN traffic")
        print("2. Return to main menu")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            source_vlan_id = input("Source VLAN ID, internet, or any: ").strip()
            destination_vlan_id = input("Destination VLAN ID, internet, or any: ").strip()

            print_vlan_path_analysis(source_vlan_id, destination_vlan_id)

        elif choice == "2":
            break

        else:
            print("Invalid option. Please try again.")


# -------------------------
# Submenu logic
# -------------------------

def vlan_menu():
    while True:
        show_vlan_menu()
        choice = input("Choose an option: ")

        if choice == "1":
            vlan_id = get_new_vlan_id()
            name = input("Name (example: Management, Servers, IoT, Guest): ")
            subnet = get_subnet()
            gateway = get_gateway_for_subnet(subnet)
            purpose = input("Purpose (why does this VLAN exist?): ")
            security_notes = input("Security notes (who should access this VLAN?): ")

            add_vlan(
                vlan_id,
                name,
                subnet,
                gateway,
                purpose,
                security_notes
            )

        elif choice == "2":
            list_vlans()

        elif choice == "3":
            vlan = select_vlan()

            if vlan is None:
                continue

            print(f"\nEditing VLAN {vlan['vlan_id']} - {vlan['name']}")
            print("Leave a field blank to keep the current value.")
            print("Subnet editing is intentionally disabled for now.")

            name = input(f"Name [{vlan['name']}]: ")
            purpose = input(f"Purpose [{vlan['purpose']}]: ")
            security_notes = input(f"Security notes [{vlan['security_notes']}]: ")

            print(f"Current gateway: {vlan['gateway']}")
            change_gateway = input("Change gateway? (y/n): ").lower()

            if change_gateway == "y":
                gateway = get_gateway_for_subnet(vlan["subnet"])
            else:
                gateway = vlan["gateway"]

            updated_vlan = {
                "vlan_id": vlan["vlan_id"],
                "name": name if name else vlan["name"],
                "subnet": vlan["subnet"],
                "gateway": gateway,
                "purpose": purpose if purpose else vlan["purpose"],
                "security_notes": security_notes if security_notes else vlan["security_notes"]
            }

            edit_vlan(vlan["vlan_id"], updated_vlan)

        elif choice == "4":
            vlan_id = get_vlan_id_to_delete()

            if vlan_id is None:
                continue

            delete_vlan(vlan_id)

        elif choice == "5":
            break

        else:
            print("Invalid option. Please try again.")


def device_menu():
    while True:
        show_device_menu()
        choice = input("Choose an option: ")

        if choice == "1":
            hostname = get_new_hostname()
            device_type = input("Device type (example: firewall, switch, access point, server, VM, client): ")

            vlan_id = get_existing_vlan_id()

            if vlan_id is None:
                print("Device was not added.")
                continue

            vlan = get_vlan_by_id(vlan_id)
            ip_address = get_ip_address_for_vlan(
                    vlan,
                    device_type
                )

            location = input("Location (example: rack, office, Proxmox host, virtual): ")
            role = input("Role (what does this device do?): ")
            notes = input("Notes (anything important, or leave blank): ")

            add_device(
                hostname,
                device_type,
                ip_address,
                vlan_id,
                location,
                role,
                notes
            )

        elif choice == "2":
            list_devices()

        elif choice == "3":
            device = select_device()

            if device is None:
                continue

            print(f"\nEditing device: {device['hostname']}")
            print("Leave a field blank to keep the current value.")

            current_vlan = get_vlan_by_id(device["vlan_id"])

            print(f"Current VLAN: {device['vlan_id']}")
            change_vlan = input("Change VLAN? (y/n): ").lower()

            if change_vlan == "y":
                vlan_id = get_existing_vlan_id()

                if vlan_id is None:
                    print("Device was not updated.")
                    continue

                vlan = get_vlan_by_id(vlan_id)
            else:
                vlan_id = device["vlan_id"]
                vlan = current_vlan

            print(f"Current IP: {device['ip_address']}")
            change_ip = input("Change IP address? (y/n): ").lower()

            if change_ip == "y":
                ip_address = get_ip_address_for_vlan(
                    vlan,
                    device_type
                )
            else:
                ip_address = device["ip_address"]

            role = input(f"Role [{device['role']}]: ")
            notes = input(f"Notes [{device['notes']}]: ")
            location = input(f"Location [{device['location']}]: ")
            device_type = input(f"Device type [{device['device_type']}]: ")

            updated_device = {
                "hostname": device["hostname"],
                "device_type": device_type if device_type else device["device_type"],
                "ip_address": ip_address,
                "vlan_id": vlan_id,
                "location": location if location else device["location"],
                "role": role if role else device["role"],
                "notes": notes if notes else device["notes"]
            }

            edit_device(device["hostname"], updated_device)

        elif choice == "4":
            hostname = get_hostname_to_delete()

            if hostname is None:
                continue

            delete_device(hostname)

        elif choice == "5":
            break

        else:
            print("Invalid option. Please try again.")


def firewall_menu():
    while True:
        show_firewall_menu()
        choice = input("Choose an option: ")

        if choice == "1":
            print("\nAdd Firewall Rule")
            print("Source VLAN = where traffic starts")
            source_vlan = get_firewall_endpoint("Source")

            if source_vlan is None:
                print("Firewall rule was not added.")
                continue

            print("\nDestination VLAN = where traffic is going")
            destination_vlan = get_firewall_endpoint("Destination")

            if destination_vlan is None:
                print("Firewall rule was not added.")
                continue

            if source_vlan == destination_vlan:
                print("Source and destination VLAN cannot be the same.")
                print("SentinelMap currently models inter-VLAN firewall rules only.")
                continue

            protocol = get_protocol()
            port = input("Port (example: 443, 80, 3389, ANY): ")
            action = get_firewall_action()
            purpose = input("Purpose (why should this traffic be allowed or denied?): ")

            if firewall_rule_exists(
                source_vlan,
                destination_vlan,
                protocol,
                port,
                action
            ):
                print("A matching firewall rule already exists.")
                print("Firewall rule was not added.")
                continue

            add_firewall_rule(
                source_vlan,
                destination_vlan,
                protocol,
                port,
                action,
                purpose
            )

        elif choice == "2":
            list_firewall_rules()

        elif choice == "3":
            rule = select_firewall_rule()

            if rule is None:
                continue

            print(f"\nEditing firewall rule {rule['rule_id']}")
            print("Leave a field blank to keep the current value.")

            print(f"Current source VLAN: {rule['source_vlan']}")
            change_source = input("Change source VLAN? (y/n): ").lower()

            if change_source == "y":
                source_vlan = get_firewall_endpoint("Source")

                if source_vlan is None:
                    print("Firewall rule was not updated.")
                    continue
            else:
                source_vlan = rule["source_vlan"]

            print(f"Current destination VLAN: {rule['destination_vlan']}")
            change_destination = input("Change destination VLAN? (y/n): ").lower()

            if change_destination == "y":
                destination_vlan = get_firewall_endpoint("Destination")

                if destination_vlan is None:
                    print("Firewall rule was not updated.")
                    continue
            else:
                destination_vlan = rule["destination_vlan"]

            if source_vlan == destination_vlan:
                print("Source and destination VLAN cannot be the same.")
                print("Firewall rule was not updated.")
                continue

            print(f"Current protocol: {rule['protocol']}")
            change_protocol = input("Change protocol? (y/n): ").lower()

            if change_protocol == "y":
                protocol = get_protocol()
            else:
                protocol = rule["protocol"]

            port = input(f"Port [{rule['port']}]: ")
            action_input = input(f"Action [{rule['action']}] change? (y/n): ").lower()

            if action_input == "y":
                action = get_firewall_action()
            else:
                action = rule["action"]

            purpose = input(f"Purpose [{rule['purpose']}]: ")

            updated_rule = {
                "rule_id": rule["rule_id"],
                "source_vlan": source_vlan,
                "destination_vlan": destination_vlan,
                "protocol": protocol,
                "port": port if port else rule["port"],
                "action": action,
                "purpose": purpose if purpose else rule["purpose"]
            }

            if firewall_rule_exists(
                source_vlan,
                destination_vlan,
                protocol,
                port if port else rule["port"],
                action,
                ignore_rule_id=rule["rule_id"]
            ):
                print("A matching firewall rule already exists.")
                print("Firewall rule was not updated.")
                continue

            edit_firewall_rule(rule["rule_id"], updated_rule)

        elif choice == "4":
            rule_id = get_rule_id_to_delete()

            if rule_id is None:
                continue

            delete_firewall_rule(rule_id)

        elif choice == "5":
            break

        else:
            print("Invalid option. Please try again.")


def switch_port_menu():
    while True:
        show_switch_port_menu()
        choice = input("Choose an option: ")

        if choice == "1":
            switch_name = input("Switch name (example: tp-link-sg2008p): ")
            
            while True:
            
                port_id = input("Port ID/number (example: 1, 2, 3): ")
                description = input("Description (example: Uplink to firewall): ")
                mode = get_switch_port_mode()
                connected_device = input("Connected device hostname/name (or leave blank): ")
                
                devices = load_devices()
                
                device_names = [device["hostname"] for device in devices]
                
                if connected_device and connected_device not in device_names:
                    print("WARNING: Connected device not found in devices.json")
                
                poe_enabled = get_poe_enabled()

                access_vlan = None
                native_vlan = None
                allowed_vlans = []
                assigned_vlan = None

                if mode == "access":
                    print("\nAccess ports belong to exactly one VLAN.")
                    access_vlan = get_existing_vlan_id()

                    if access_vlan is None:
                        print("Switch port was not added.")
                        continue

                elif mode == "trunk":
                    print("\nTrunk ports carry multiple VLANs.")
                    print("Native VLAN should usually be an unused/parking VLAN in this lab.")
                    native_vlan = get_existing_vlan_id()

                    if native_vlan is None:
                        print("Switch port was not added.")
                        continue

                    allowed_vlans = get_allowed_vlans()

                elif mode == "unused":
                    print("\nUnused ports should be assigned to a safe parking VLAN, such as VLAN 90 BLACKHOLE.")
                    assigned_vlan = get_existing_vlan_id()

                    if assigned_vlan is None:
                        print("Switch port was not added.")
                        continue

                notes = input("Notes (why is this port configured this way?): ")

                add_switch_port(
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
                )

                another = input(
                    f"Add another port to {switch_name}? (yes/no)" 
                ).strip().lower()

                if another != "yes":
                    break

        elif choice == "2":
            list_switch_ports()

        elif choice == "3":
            switch_port = select_switch_port()

            if switch_port is None:
                continue

            print(
                f"\nEditing {switch_port['switch_name']} "
                f"port {switch_port['port_id']}"
            )
            print("Leave a field blank to keep the current value.")
            print("Mode editing is intentionally disabled for now.")

            description = input(f"Description [{switch_port['description']}]: ")
            connected_device = input(f"Connected device [{switch_port['connected_device']}]: ")
            
            devices = load_devices()
            
            device_names = [device["hostname"] for device in devices]
            
            if connected_device and connected_device not in device_names:
                print("WARNING: Connected device not found in devices.json")

            notes = input(f"Notes [{switch_port['notes']}]: ")

            print(f"Current PoE enabled: {switch_port['poe_enabled']}")
            change_poe = input("Change PoE setting? (y/n): ").lower()

            if change_poe == "y":
                poe_enabled = get_poe_enabled()
            else:
                poe_enabled = switch_port["poe_enabled"]

            access_vlan = switch_port["access_vlan"]
            native_vlan = switch_port["native_vlan"]
            allowed_vlans = switch_port["allowed_vlans"]
            assigned_vlan = switch_port["assigned_vlan"]

            if switch_port["mode"] == "access":
                print(f"Current access VLAN: {access_vlan}")
                change_vlan = input("Change access VLAN? (y/n): ").lower()

                if change_vlan == "y":
                    access_vlan = get_existing_vlan_id()

                    if access_vlan is None:
                        print("Switch port was not updated.")
                        continue

            elif switch_port["mode"] == "trunk":
                print(f"Current native VLAN: {native_vlan}")
                change_native = input("Change native VLAN? (y/n): ").lower()

                if change_native == "y":
                    native_vlan = get_existing_vlan_id()

                    if native_vlan is None:
                        print("Switch port was not updated.")
                        continue

                print(f"Current allowed VLANs: {allowed_vlans}")
                change_allowed = input("Change allowed VLANs? (y/n): ").lower()

                if change_allowed == "y":
                    allowed_vlans = get_allowed_vlans()

            elif switch_port["mode"] == "unused":
                print(f"Current assigned VLAN: {assigned_vlan}")
                change_assigned = input("Change assigned VLAN? (y/n): ").lower()

                if change_assigned == "y":
                    assigned_vlan = get_existing_vlan_id()

                    if assigned_vlan is None:
                        print("Switch port was not updated.")
                        continue

            updated_switch_port = {
                "switch_name": switch_port["switch_name"],
                "port_id": switch_port["port_id"],
                "description": description if description else switch_port["description"],
                "mode": switch_port["mode"],
                "connected_device": connected_device if connected_device else switch_port["connected_device"],
                "poe_enabled": poe_enabled,
                "access_vlan": access_vlan,
                "native_vlan": native_vlan,
                "allowed_vlans": allowed_vlans,
                "assigned_vlan": assigned_vlan,
                "notes": notes if notes else switch_port["notes"]
            }

            edit_switch_port(
                switch_port["switch_name"],
                switch_port["port_id"],
                updated_switch_port
            )

        elif choice == "4":
            switch_port_identity = get_switch_port_identity_to_delete()

            if switch_port_identity is None:
                continue

            switch_name, port_id = switch_port_identity
            delete_switch_port(switch_name, port_id)

        elif choice == "5":
            break

        else:
            print("Invalid option. Please try again.")


# -------------------------
# Main app loop
# -------------------------

def main():
    while True:
        show_main_menu()
        choice = input("Choose an option: ")

        if choice == "1":
            vlan_menu()

        elif choice == "2":
            device_menu()

        elif choice == "3":
            firewall_menu()

        elif choice == "4":
            switch_port_menu()

        elif choice == "5":
            show_traffic_summary()

        elif choice == "6":
            generate_markdown_report()

        elif choice == "7":
            run_integrity_check()

        elif choice == "8":
            traffic_path_menu()

        elif choice == "9":
            print("Exiting SentinelMap.")
            break

        else:
            print("Invalid option. Please try again.")


main()