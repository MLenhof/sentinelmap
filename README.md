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

## Traffic Analysis
- Show “what can talk to what” summaries
- Display inter-VLAN traffic relationships
- Explain firewall intent through rule purposes

## Reporting
- Generate Markdown infrastructure reports
- Include VLAN summaries
- Include device summaries
- Include firewall summaries
- Include traffic summaries
- Include report timestamps

## Integrity Checking
- Detect duplicate hostnames
- Detect duplicate IP addresses
- Detect duplicate subnets
- Detect duplicate gateways
- Detect invalid VLAN references
- Detect invalid firewall rule references
- Detect invalid subnet relationships
- Detect invalid gateway assignments

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
│   └── firewall_rules.json
│
├── modules/
│   ├── vlan_manager.py
│   ├── device_manager.py
│   ├── firewall_manager.py
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
4. Generate traffic summaries
5. Run integrity checks
6. Generate Markdown documentation reports

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

- Switch port documentation
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

---

# SentinelMap Philosophy

SentinelMap is not intended to become a massive enterprise management platform.

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