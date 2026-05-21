# SentinelMap

SentinelMap is a local-first Python infrastructure documentation and reasoning tool designed for homelabs and small enterprise-style environments.

The goal of SentinelMap is not just to store inventory, but to help users understand how infrastructure components relate to each other through validation, traffic reasoning, integrity checking, and documentation generation.

SentinelMap was created as part of the SentinelLab homelab project to improve understanding of:

- VLAN segmentation
- network design
- firewall policy reasoning
- infrastructure relationships
- documentation practices
- infrastructure validation
- enterprise troubleshooting concepts

SentinelMap is evolving from a documentation utility into an infrastructure reasoning engine capable of validating relationships between VLANs, devices, switch ports, firewall rules, and traffic paths.

SentinelMap is evolving into an infrastructure reasoning engine capable of analyzing VLAN relationships, firewall policy intent, switch topology, device connectivity, and traffic paths.

---

# Current Features

## VLAN Management
- Add VLANs
- List VLANs
- Edit VLANs
- Delete VLANs
- Validate VLAN IDs
- Validate subnet formatting
- Validate gateway/subnet relationships

## Device Management
- Add devices
- List devices
- Edit devices
- Delete devices
- Validate device IPs belong to VLAN subnets
- Prevent duplicate hostnames
- Prevent duplicate IP addresses
- Prevent gateway/device IP conflicts

## Firewall Rule Management
- Add firewall rules
- List firewall rules
- Edit firewall rules
- Delete firewall rules
- Prevent duplicate firewall rules
- Prevent invalid source/destination relationships

## Switch Port Management
- Add switch ports
- List switch ports
- Edit switch ports
- Delete switch ports
- Model access/trunk/unused ports
- Validate VLAN references
- Validate switch port relationships
- Detect duplicate switch port assignments
- Detect unknown connected devices

## Traffic Path Analysis
- Analyze VLAN-to-VLAN traffic paths
- Analyze device-to-device traffic paths
- Interpret firewall rule intent
- Detect broad vs partial access
- Support special endpoints like internet and any
- Explain why traffic is allowed or denied
- Display matching firewall rules

## Reporting
- Generate Markdown infrastructure reports
- Include integrity validation summaries
- Include VLAN summaries
- Include device summaries
- Include firewall summaries
- Include traffic summaries
- Include switch port summaries
- Include physical topology summaries
- Include report timestamps
- Include physical topology summaries
- Include integrity validation summaries
- Include traffic path reasoning summaries

## Integrity Checking
- Detect duplicate hostnames
- Detect duplicate IP addresses
- Detect duplicate subnets
- Detect duplicate gateways
- Detect invalid VLAN references
- Detect invalid firewall rule references
- Detect invalid subnet relationships
- Detect invalid gateway assignments
- Detect unknown switch-connected devices
- Detect devices without switch connectivity
- Detect duplicate switch port assignments
- Validate switch port VLAN references
- Validate access/trunk port configurations
- Detect devices without switch connectivity
- Detect unknown switch-connected devices
- Detect invalid switch port relationships

---

# Project Structure

```text
sentinelmap/
│
├── main.py
│
├── data/
│   ├── vlans.json
│   ├── devices.json
│   ├── firewall_rules.json
│   └── switch_ports.json
│
├── modules/
│   ├── vlan_manager.py
│   ├── device_manager.py
│   ├── firewall_manager.py
│   ├── switch_port_manager.py
│   ├── traffic_analyzer.py
│   ├── report_generator.py
│   └── integrity_checker.py
│
└── reports/
    └── network_report.md
```

---

# Design Principles

SentinelMap is intentionally designed to be:

- beginner-friendly
- modular
- easy to expand
- local-only
- JSON-based
- enterprise-inspired
- validation-focused
- infrastructure-reasoning oriented

The project intentionally avoids:
- cloud uploads
- databases (for MVP)
- GUI complexity (for MVP)
- unnecessary abstraction

---

# How To Run

## Requirements

- Python 3.10+
- No external Python packages currently required

## Run SentinelMap

```bash
python main.py
```

---

# Example Workflow

1. Create VLANs
2. Add devices to VLANs
3. Create firewall rules between VLANs
4. Document switch ports and topology
5. Generate traffic summaries
6. Run integrity checks
7. Generate Markdown documentation reports

---

# Example Use Cases

- Homelab documentation
- Learning VLAN segmentation
- Learning firewall relationships
- Infrastructure validation practice
- Enterprise-style documentation practice
- Network troubleshooting reasoning
- Portfolio projects
- Cybersecurity learning labs

---

# Future Roadmap

Potential future additions:

- Proxmox host tracking
- VM tracking
- Wireless SSID modeling
- Topology visualization
- YAML export
- Diagram generation
- Configuration backup integration
- ACL modeling
- Route modeling
- DICOM/PACS infrastructure mapping
- Infrastructure change history
- Search functionality
- Risk scoring
- Compliance mapping
- VLAN path reasoning
- Route/path tracing
- Topology graph generation

---

# SentinelMap Philosophy

SentinelMap is not intended to become a massive enterprise management platform.

SentinelMap focuses on helping users understand not only what infrastructure exists, but how infrastructure components interact, communicate, and enforce segmentation boundaries.

The purpose is to:

- understand infrastructure relationships
- improve troubleshooting intuition
- practice enterprise documentation
- model network behavior
- safely experiment
- learn through implementation

The focus is understanding *why* infrastructure works, not just storing data.

---

# License

This project is currently intended for personal learning and homelab development.