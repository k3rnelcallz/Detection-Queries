// detection name: PowerShell Hidden Download to Temp
// technique: T1059.001 (PowerShell), T1105 (Ingress Tool Transfer)
// description: Detects powershell that executes hidden window
// that downloads a remote payload using webclient and writes a batch file to Temp
// Common malware loader and stager behavior


index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*\\powershell.exe"
CommandLine="*"
| search CommandLine="*WindowStyle Hidden*" OR CommandLine="*hidden*"
| search CommandLine="*DownloadFile*" OR CommandLine="*System.Net.WebClient*" OR CommandLine="*[Net.ServicePointManager]*" OR CommandLine="*Tls12*"
| search CommandLine="*\\AppData\\Local\\Temp*" CommandLine="*.bat"
| table _time, Computer, Image, CommandLine, ParentImage, ParentCommandLine, IntegrityLevel, User
