## Detection name: behavior based wscript powershell execution

Description: detects wscript powershell execution

Mitre-techinques: T1059.005, T1059.001

---

```kql
DeviceProcessEvents
| where InitiatingProcessFileName =~ "wscript.exe"
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any (
    "FromBase64String",
    "IEX",
    "Unicode.GetString"
)
| project
    Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FileName,
    ProcessCommandLine,
    SHA256
| order by Timestamp desc
```
