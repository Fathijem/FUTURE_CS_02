# Internal Connection Attempt Alert

## Description
Detects connection attempts from internal private IP ranges.

## Severity
**Low**

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
| search severity="Low"
| table _time user ip action severity
| sort _time
```
<img width="1893" height="837" alt="Unusual_Connection Attempt_InternalNetwork" src="https://github.com/user-attachments/assets/a128be80-d814-4fa5-860a-3a380adc40e4" />


## Trigger Condition
Any new internal connection attempt logged.
Give severity rating of low as it involves internal network and employees.
Set schedule: Every 15 mins or real time a
<img width="999" height="755" alt="image" src="https://github.com/user-attachments/assets/b5304d10-a008-424b-afae-13799847e638" />


## Viewing Alerts
All alerts can be viewed by clicking on the activity (top right corner). In the drop view, click on triggered alerts -> AfterHour Login -> View results to analyse the alerts and the details.
<img width="1880" height="515" alt="image" src="https://github.com/user-attachments/assets/e917c2cb-cb24-44f7-9b6e-8be7b45ab292" />


## Recommended Response
Verify the source and intended target.
Ensure access controls are correctly applied.
