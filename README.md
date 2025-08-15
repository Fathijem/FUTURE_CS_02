# SOC Alert & Dashboard Project

## Overview
This project simulates a Security Operations Center (SOC) workflow using **Splunk** to detect and visualize suspicious activities such as:
- After-hours logins
- Internal & external connection attempts
- Malware detection (Trojan, Rootkit, Spyware, Ransomware, Worm)
- File access from unusual IPs

The goal is to:
- Parse logs and extract security-relevant fields
- Create targeted alerts
- Classify incidents by severity
- Visualize activity in a Splunk dashboard

---

## Tools Used
- **Splunk Enterprise (Free Trial)** – SIEM & log analysis
- **Sample SOC Logs** – Provided dataset
- **Markdown / GitHub** – Documentation

---

## Setup
Full setup instructions are available in [`docs/setup_guide.md`](docs/setup_guide.md).

---

## Features
- **8 SOC Alerts**:
  1. AfterHour_Login
  2. Connection Attempt
  3. External Connection Attempt
  4. Ransomware Detected
  5. Rootkit Alert
  6. Spyware Detected
  7. Trojan Alert
  8. Worm Infection Alert

- **Severity Classification**:
  - High, Medium, Low – based on detection type and IP source

- **Dashboard Visualization**:
  - Real-time and historical trends
  - Malware detection counts
  - After-hours activity map
 
- **Incident Response Documentation**:
  - Alert analysis and classification
  - Impact assessment
  - Remediation recommendations
  - Communication template for stakeholders

---

## Alerts Implemented
| Alert Name                   | Description |
|------------------------------|-------------|
| AfterHour_Login              | Detects unusual login attempts outside working hours |
| Connection Attempt           | Internal network connection attempts after-hours |
| External Connection Attempt  | External IP connection attempts after-hours |
| Ransomware Detected          | Detects ransomware-related suspicious activity |
| Rootkit Alert                | Detects rootkit signatures |
| Spyware Detected             | Detects spyware activity |
| Trojan Alert                 | Detects trojan activity |
| Worm Infection Alert         | Detects worm infection attempts |

---

## Incident Severity Mapping
Refer to [`docs/severity_mapping.md`](docs/severity_mapping.md) for detailed classification rules.

---

