# Detection Logic – Splunk SOC Simulation

This document explains the SPL (Search Processing Language) logic for each detection used in the SOC Dashboard.

---

## 1. After-Hour Login
**Description:** Detects successful logins outside of standard business hours (09:00–19:00).  
**Severity:** Medium (unless combined with malware indicators).

```spl
source="SOC_Task2_Sample_Logs.csv"
| rex field=_raw "user=(?<user>\S+)"
| rex field=_raw "ip=(?<ip>\S+)"
| rex field=_raw "action=(?<action>[^|]+)"
| eval hour=strftime(_time,"%H")
| search action="login success" OR action="login failed"
| where hour < 9 OR hour > 19
| table _time user ip action hour
| sort _time
```

<img width="1896" height="842" alt="Unusual_Login" src="https://github.com/user-attachments/assets/84c5d7af-693f-451f-a8bf-0096820827cb" />


## 2. Internal Connection Attempt
Description: Detects connection attempt events from private IP ranges.
Severity: Low.
``` spl
source="SOC_Task2_Sample_Logs.csv"
| rex field=_raw "ip=(?<ip>\S+)"
| search action="connection attempt"
| regex ip="^(10\.|172\.16\.|192\.168\.)"
| table _time ip action

```

<img width="1893" height="837" alt="Unusual_Connection Attempt_InternalNetwork" src="https://github.com/user-attachments/assets/250bcd8e-8bc0-4542-a93a-569ed635b1f4" />

## 3. External Connection Attempt
Description: Detects connection attempt events from public IP addresses.
Severity: Medium.
```spl
source="SOC_Task2_Sample_Logs.csv"
| rex field=_raw "ip=(?<ip>\S+)"
| search action="connection attempt"
| where NOT (like(ip,"10.%") OR like(ip,"172.16.%") OR like(ip,"192.168.%"))
| table _time ip action
```

<img width="1882" height="866" alt="Unusual_Connection Attempt_ExternalNetwork" src="https://github.com/user-attachments/assets/60a9a323-9bfb-432b-ac84-c1c195f9314a" />

## 4. Ransomware Detection
Description: Detects threats with “Ransomware” in the threat field.
Severity: High.
```spl
source="SOC_Task2_Sample_Logs.csv"
| rex field=_raw "threat=(?<threat>.+)"
| search threat="*Ransomware*"
| table _time user ip threat
```

