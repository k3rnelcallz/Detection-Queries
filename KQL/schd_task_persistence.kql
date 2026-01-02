// detection name: Scheduled task persistence via schtask.exe
// techinque: T1053.005 (Scheduled Task)
// description: Detects scheduled tasks that creates persistence 
// on logon by launching a batch file from temp path 
// Frequently used persistence mechanism


DeviceProcessEvents
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("onlogon", "onstartup", "logon", "reboot")
| where ProcessCommandLine has_any (@'\AppData\Local\Temp', ".bat")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName, SHA256
