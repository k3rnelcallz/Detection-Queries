// detection name: Scheduled task persistence via schtask.exe
// techinque: T1053.005 (Scheduled Task)
// description: Detects scheduled tasks that creates persistence 
// on logon by launching a batch file from temp path 
// Frequently used persistence mechanism


index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*\\schtasks.exe"
| search CommandLine="*/create*"
| search CommandLine="*onlogon*" OR CommandLine="*onstartup*" OR CommandLine="*logon*" OR CommandLine="*reboot*"
| search CommandLine="*\\AppData\\Local\\Temp*" CommandLine="*.bat"
| table _time, Computer, Image, CommandLine, ParentImage, ParentCommandLine, IntegrityLevel, User
