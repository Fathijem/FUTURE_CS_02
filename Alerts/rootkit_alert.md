# Rootkit Alert

## Description
Rootkit is a stealthy malware designed to hide its presence and enable persistent privileged access to a system, often bypassing standard detection methods. Alerts are trigged when "Rootkit" is detected in the threat field or any suspicious activites happening in the system.

## Severity
**Critical**

## SPL Query
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

## Trigger Condition
Any rootkit detection in logs.
<img width="996" height="753" alt="image" src="https://github.com/user-attachments/assets/7b9fcb32-3e45-45cc-9407-24d2d689ee18" />


## Viewing Alerts
All alerts can be viewed by clicking on the activity (top right corner) for more details steps go to [`alerts/afterhour_login.md`](alerts/afterhour_login.md). In the drop view, click on triggered alerts -> ConnectionAttempt Login -> View results to analyse the alerts and the details.
<img width="1893" height="773" alt="image" src="https://github.com/user-attachments/assets/d5cdc7fa-1904-4616-b061-445b5503a419" />


## Recommended Response
1. Isolate the system.
2. Conduct a forensic investigation.
3. Rebuild OS if confirmed.
