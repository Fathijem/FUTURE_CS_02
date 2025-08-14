# After-Hour Login Alert

## Description
Detects successful logins outside the standard business hours (09:00–19:00).  
Potential indicator of compromised accounts or insider threats.

## Severity
**Medium** – Escalates to High if followed by suspicious activity.

## SPL Query
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

<img width="1896" height="842" alt="Unusual_Login" src="https://github.com/user-attachments/assets/e7b6744a-f681-41e3-baa0-321e261c5158" />


## Trigger Condition
Trigger: Choose pre-result for uploaded log files. If you're analysing real-time data set trigger result > 0.

Schedule: Every 15 minutes or real-time
<img width="996" height="744" alt="image" src="https://github.com/user-attachments/assets/5d9e88bc-ca2b-4b23-bd9d-52f52ad7ee2a" />

## Viewing Alerts
All alerts can be viewed by clicking on the activity (top right corner). 
<img width="1897" height="889" alt="image" src="https://github.com/user-attachments/assets/90311cf1-2e5c-43bd-8f09-3006770d0f5e" />


It will display all the alerts captured after analysis of the logs.
<img width="1882" height="880" alt="image" src="https://github.com/user-attachments/assets/839183ca-cfff-405e-b523-abde7511da5b" />

To view a particular alert,  click on AfterHour Login -> View results to analyse the alerts and the details.
<img width="1887" height="882" alt="image" src="https://github.com/user-attachments/assets/2a1cff11-1b1d-4805-870e-5edadc3ea585" />


You can also visualize the results by clicking the "Visualization" next to "Statistics"
<img width="1887" height="535" alt="image" src="https://github.com/user-attachments/assets/e379504b-b5b3-4eb1-9854-49820b8a001f" />


## Recommended Response
1. Validate the login with the user.
2. Check if IP is recognized.
3. Monitor for further suspicious activity.
