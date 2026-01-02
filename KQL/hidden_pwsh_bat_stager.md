// detection name: PowerShell Hidden Download to Temp
// technique: T1059.001 (PowerShell), T1105 (Ingress Tool Transfer)
// description: Detects powershell that executes hidden window
// that downloads a remote payload using webclient and writes a batch file to Temp
// Common malware loader and stager behavior


DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-WindowStyle Hidden", "hidden")
| where ProcessCommandLine has_any ("DownloadFile", "System.Net.WebClient", "[Net.ServicePointManager]", "Tls12")
| where ProcessCommandLine has_any (@'\AppData\Local\Temp', ".bat")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, AccountName, SHA256
