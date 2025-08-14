# Worm Infection Alert

## Description
Worm is a self-replicating malware that spreads across networks without user intervention, often exploiting vulnerabilities to infect multiple systems quickly. Alert is trrigered when "Worm" is detected in the threat field.

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
| search malware_type="Worm Infection"
| table _time user ip action threat malware_type
```

## Trigger Condition
Any worm detection in logs.
<img width="997" height="748" alt="image" src="https://github.com/user-attachments/assets/cb6cfba7-5b76-48cf-8661-d028e18b04f1" />


## Viewing Alerts
All alerts can be viewed by clicking on the activity (top right corner) for more details steps go to [`alerts/afterhour_login.md`](alerts/afterhour_login.md). In the drop view, click on triggered alerts -> ConnectionAttempt Login -> View results to analyse the alerts and the details.
<img width="1882" height="687" alt="image" src="https://github.com/user-attachments/assets/e25c966a-033d-4272-8743-f9fff054cb6a" />


## Recommended Response
1. Isolate infected machine.
2. Scan other systems for worm activity.
3. Block related IPs or domains.
