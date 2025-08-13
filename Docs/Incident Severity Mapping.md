# Incident Severity Mapping

| Severity | Criteria |
|----------|----------|
| **High** | Malware detected (Trojan, Rootkit, Ransomware, Worm) OR multiple detections on same host within a short timeframe. |
| **Medium** | After-hours successful logins from public IP, multiple failed logins from external IP, suspicious file access from unusual IPs. |
| **Low** | Single failed login attempt from internal IP or connection attempt from private IP range. |

---

## Example Mapping
- bob@10.0.0.5 — Trojan Detected → **High**
- alice@198.51.100.42 — Rootkit Signature → **High**
- bob@203.0.113.77 — Worm Infection Attempt → **High**
- login failures from 203.0.113.77 → **Medium**
- file accessed by user on external IP → **Medium**
- connection attempt from 172.16.0.3 → **Low**

---
