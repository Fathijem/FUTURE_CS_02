# Spyware Alert

## Description
Spyware is a malware that secretly collects user data, such as credentials, browsing habits, or personal files, and sends it to an attacker without consent. Triggers when "Spyware" is detected in the threat field.

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
| search malware_type="Spyware"
| table _time user ip action threat malware_type
```

## Trigger Condition
Any spyware detection in logs.
<img width="997" height="748" alt="image" src="https://github.com/user-attachments/assets/cb6cfba7-5b76-48cf-8661-d028e18b04f1" />


## Viewing Alerts
All alerts can be viewed by clicking on the activity (top right corner) for more details steps go to [`alerts/afterhour_login.md`](alerts/afterhour_login.md). In the drop view, click on triggered alerts -> ConnectionAttempt Login -> View results to analyse the alerts and the details.
<img width="1878" height="702" alt="image" src="https://github.com/user-attachments/assets/eec64f88-1053-4ed8-8cfa-79b75afeb94f" />


## Recommended Response
1. Remove spyware immediately.
2. Reset credentials if sensitive data was accessed.
