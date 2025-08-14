# Trojan Alert

## Description
Trojan is a malware disguised as legitimate software that allows attackers to gain unauthorized access or control over a system. Often used to drop additional malicious payloads. Triggers alert when "Trojan" is detected in the threat field.

## Severity
**High**

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
| search malware_type="Trojan"
| table _time user ip action threat malware_type
```
<img width="1892" height="783" alt="image" src="https://github.com/user-attachments/assets/4b51b6a3-c0be-452e-ad0f-0d74db96ce71" />


## Trigger Condition
Any trojan detection in logs.
<img width="997" height="748" alt="image" src="https://github.com/user-attachments/assets/cb6cfba7-5b76-48cf-8661-d028e18b04f1" />

## Viewing Alerts
All alerts can be viewed by clicking on the activity (top right corner) for more details steps go to [`alerts/afterhour_login.md`](alerts/afterhour_login.md). In the drop view, click on triggered alerts -> ConnectionAttempt Login -> View results to analyse the alerts and the details.
<img width="1880" height="852" alt="image" src="https://github.com/user-attachments/assets/654f1202-1240-4b0c-a67f-9573108bc129" />


## Recommended Response
1. Isolate system.
2. Scan and remove trojan.
3. Investigate source of infection.
