## Description:
 - Detection name: Scheduled task persistence via schtask.exe
 - Techinque: T1053.005 (Scheduled Task)
 - Detects scheduled tasks that creates persistence on logon by launching a batch file from temp path 
 - Frequently used persistence mechanism

#### Query
---
```SPL
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*\\schtasks.exe"
| search CommandLine="*/create*"
| search CommandLine="*onlogon*" OR CommandLine="*onstartup*" OR CommandLine="*logon*" OR CommandLine="*reboot*"
| search CommandLine="*\\AppData\\Local\\Temp*" CommandLine="*.bat"
| table _time, Computer, Image, CommandLine, ParentImage, ParentCommandLine, IntegrityLevel, User
```