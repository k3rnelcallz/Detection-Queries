# Detection Name: Obfuscated Powershell VBS execution

## Description:  File Content & Process Check
### References: Sha: "561e3780b6c1d17074806312b5f77378d8a9ac8088cc44389fb8a7f1b73850eb"
###             Tags: "vbs, REMCOS, html, downloader, Trojan, dwnldr, obfuscated"


**Techniques**
T1059.001 - PowerShell 
T1059.005 - Visual Basic
T1546.015 - Component Object Hijacking
T1027 - Obfuscation



````KQL
// Detect COM Object manipulation with PowerShell obfuscation patterns
let ComObjectPatterns = dynamic(["adodb.stream", "msxml2.domdocument"]);
let PowerShellPatterns = dynamic(["createelement", "bypass", "powershell", "-nop -w"]);
let VBSPatterns = dynamic(["createobject", "expandenvironmentstrings"]);

union DeviceProcessEvents, DeviceFileEvents, DeviceScriptEvents
| where TimeGenerated >= ago(24h)
| extend LowerCommandLine = tolower(ProcessCommandLine),
         LowerFileName = tolower(FileName),
         LowerFileContent = tolower(FileContent)
| where 
    // COM Object manipulation (all required)
    (LowerCommandLine has "adodb.stream" and LowerCommandLine has "msxml2.domdocument")
    or
    // PowerShell patterns (3 of 4 required)
    (
        (iff(LowerCommandLine has "createelement", 1, 0) +
         iff(LowerCommandLine has "bypass", 1, 0) +
         iff(LowerCommandLine has "powershell", 1, 0) +
         iff(LowerCommandLine has "-nop -w", 1, 0)) >= 3
    )
    or
    // VBS patterns (all required)
    (LowerCommandLine has "createobject" and LowerCommandLine has "expandenvironmentstrings")
| where FileName endswith ".hta" or FileName endswith ".vbs" or FileName endswith ".js"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
````

### Network IOC Detection

### Detect connections to known malicious IP

```
DeviceNetworkEvents
| where TimeGenerated >= ago(24h)
| where RemoteIP == "107.173.47.137"
    or RemoteUrl contains "107.173.47.137"
    or RemoteUrl contains "wellthingsformebest.js"
| project TimeGenerated, DeviceName, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName


