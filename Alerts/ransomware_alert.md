# Ransomware Alert

## Description
Ransomware is a malware that encrypts files or locks systems, demanding payment (ransom) from the victim to restore access. Triggers alert when a log contains the keyword "Ransomware" in the threat field.

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
| search malware_type="Ransomware"
| table _time user ip action threat malware_type
```
<img width="1897" height="782" alt="image" src="https://github.com/user-attachments/assets/1ba83886-74ba-4a76-b589-9666a5d4e5e9" />


## Trigger Condition
Any detection of ransomware.
<img width="997" height="748" alt="image" src="https://github.com/user-attachments/assets/cb6cfba7-5b76-48cf-8661-d028e18b04f1" />


## Viewing Alerts
All alerts can be viewed by clicking on the activity (top right corner) for more details steps go to [`alerts/afterhour_login.md`](alerts/afterhour_login.md). In the drop view, click on triggered alerts -> ConnectionAttempt Login -> View results to analyse the alerts and the details.
<img width="1876" height="705" alt="image" src="https://github.com/user-attachments/assets/b18c7d16-0640-4569-8dd1-d0820762f513" />


## Recommended Response
1. Isolate affected hosts immediately.
2. Disable network connections to prevent spread.
3. Begin incident response procedures.
