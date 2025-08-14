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
**Description:** Detects connection attempt events from private IP ranges.

**Severity:** Low.
``` spl
source="SOC_Task2_Sample_Logs.csv"
| rex field=_raw "user=(?<user>\S+)"
| rex field=_raw "ip=(?<ip>\S+)"
| rex field=_raw "action=(?<action>[^|]+)"
| search action="connection attempt"
| eval severity=case(
    match(ip, "^10\."), "Low",
    match(ip, "^192\.168\."), "Low",
    match(ip, "^172\.(1[6-9]|2[0-9]|3[0-1])\."), "Low",
    true(), "Medium"
)
| search severity="Low"
| table _time user ip action severity
| sort _time


```

<img width="1893" height="837" alt="Unusual_Connection Attempt_InternalNetwork" src="https://github.com/user-attachments/assets/250bcd8e-8bc0-4542-a93a-569ed635b1f4" />

## 3. External Connection Attempt
**Description:** Detects connection attempt events from public IP addresses.

**Severity:** Medium.
```spl
source="SOC_Task2_Sample_Logs.csv"
| rex field=_raw "user=(?<user>\S+)"
| rex field=_raw "ip=(?<ip>\S+)"
| rex field=_raw "action=(?<action>[^|]+)"
| search action="connection attempt"
| eval severity=case(
    match(ip, "^10\."), "Low",
    match(ip, "^192\.168\."), "Low",
    match(ip, "^172\.(1[6-9]|2[0-9]|3[0-1])\."), "Low",
    true(), "Medium"
)
| search severity="Medium"
| table _time user ip action severity
| sort _time

```

<img width="1882" height="866" alt="Unusual_Connection Attempt_ExternalNetwork" src="https://github.com/user-attachments/assets/60a9a323-9bfb-432b-ac84-c1c195f9314a" />

## 4. Ransomware Detection
**Description:** Detects threats with “Ransomware” in the threat field.

**Severity:** High.
```spl
source="SOC_Task2_Sample_Logs.csv"
| rex field=_raw "user=(?<user>\S+)"
| rex field=_raw "ip=(?<ip>\S+)"
| rex field=_raw "action=(?<action>[^|]+)"
| rex field=_raw "threat=(?<threat>.+)"
| eval malware_type=case(
  match(threat, "(?i)Trojan"), "Trojan",
  match(threat, "(?i)Rootkit"), "Rootkit",
  match(threat, "(?i)Spyware"), "Spyware",
  match(threat, "(?i)Ransomware"), "Ransomware",
  match(threat, "(?i)Worm"), "Worm Infection", true(), "Other" )
| search malware_type="Ransomware"
| table _time user ip action threat malware_type

```


## 5. Rootkit Detection
**Description:** Detects threats with “Rootkit” signatures.

**Severity:** High.
```spl
source="SOC_Task2_Sample_Logs.csv"
| rex field=_raw "user=(?<user>\S+)"
| rex field=_raw "ip=(?<ip>\S+)"
| rex field=_raw "action=(?<action>[^|]+)"
| rex field=_raw "threat=(?<threat>.+)"
| eval malware_type=case(
  match(threat, "(?i)Trojan"), "Trojan",
  match(threat, "(?i)Rootkit"), "Rootkit",
  match(threat, "(?i)Spyware"), "Spyware",
  match(threat, "(?i)Ransomware"), "Ransomware",
  match(threat, "(?i)Worm"), "Worm Infection", true(), "Other" )
| search malware_type="Rootkit"
| table _time user ip action threat malware_type
```

## 6. Spyware Detection
**Description:** Detects threats with “Spyware” in the threat field.

**Severity:** High.
```spl
source="SOC_Task2_Sample_Logs.csv"
| rex field=_raw "user=(?<user>\S+)"
| rex field=_raw "ip=(?<ip>\S+)"
| rex field=_raw "action=(?<action>[^|]+)"
| rex field=_raw "threat=(?<threat>.+)"
| eval malware_type=case(
  match(threat, "(?i)Trojan"), "Trojan",
  match(threat, "(?i)Rootkit"), "Rootkit",
  match(threat, "(?i)Spyware"), "Spyware",
  match(threat, "(?i)Ransomware"), "Ransomware",
  match(threat, "(?i)Worm"), "Worm Infection", true(), "Other" )
| search malware_type="Spyware"
| table _time user ip action threat malware_type
```

## 7. Trojan Detection
**Description:** Detects threats with “Trojan” in the threat field.

**Severity:** High.
```spl
source="SOC_Task2_Sample_Logs.csv"
| rex field=_raw "user=(?<user>\S+)"
| rex field=_raw "ip=(?<ip>\S+)"
| rex field=_raw "action=(?<action>[^|]+)"
| rex field=_raw "threat=(?<threat>.+)"
| eval malware_type=case(
  match(threat, "(?i)Trojan"), "Trojan",
  match(threat, "(?i)Rootkit"), "Rootkit",
  match(threat, "(?i)Spyware"), "Spyware",
  match(threat, "(?i)Ransomware"), "Ransomware",
  match(threat, "(?i)Worm"), "Worm Infection", true(), "Other" )
| search malware_type="Trojan"
| table _time user ip action threat malware_type
```

## 8. Worm Infection Detection
**Description:** Detects threats with “Worm” in the threat field.

**Severity:** High.
```spl
source="SOC_Task2_Sample_Logs.csv"
| rex field=_raw "user=(?<user>\S+)"
| rex field=_raw "ip=(?<ip>\S+)"
| rex field=_raw "action=(?<action>[^|]+)"
| rex field=_raw "threat=(?<threat>.+)"
| eval malware_type=case(
  match(threat, "(?i)Trojan"), "Trojan",
  match(threat, "(?i)Rootkit"), "Rootkit",
  match(threat, "(?i)Spyware"), "Spyware",
  match(threat, "(?i)Ransomware"), "Ransomware",
  match(threat, "(?i)Worm"), "Worm Infection", true(), "Other" )
| search malware_type="Worm Infection"
| table _time user ip action threat malware_type
```









