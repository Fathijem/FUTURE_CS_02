# External Connection Attempt Alert

## Description
Detects connection attempts from external/public IP addresses.

## Severity
**Medium**

## SPL Query
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
<img width="1882" height="866" alt="image" src="https://github.com/user-attachments/assets/ff52e355-8cce-47bd-917e-4399ae5640f9" />



## Trigger Condition
Any event from an IP that is not in private ranges.
<img width="1000" height="751" alt="image" src="https://github.com/user-attachments/assets/76a23310-2899-46c0-aca6-814391a31432" />


## Viewing Alerts
All alerts can be viewed by clicking on the activity (top right corner) for more details steps go to [`alerts/afterhour_login.md`](alerts/afterhour_login.md). In the drop view, click on triggered alerts -> ConnectionAttempt Login -> View results to analyse the alerts and the details.
<img width="1879" height="691" alt="image" src="https://github.com/user-attachments/assets/16957823-a400-421c-8883-14e51c2ac325" />


## Recommended Response
1. Investigate the external IP using threat intelligence tools.
2. Block malicious IPs if confirmed.
