#detection name: behavior based wscript powershell execution
##description: detects wscript powershell execution
//techinque: T1059.005, T1059.001 

'''
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
'''