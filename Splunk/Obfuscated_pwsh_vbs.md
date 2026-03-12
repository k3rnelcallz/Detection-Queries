## Description: 
- Detection for Malicious HTA with obfuscated VBS 
- Techniques Used: 
```
T1059.001 - PowerShell 
T1059.005 - Visual Basic
T1546.015 - Component Object Hijacking
T1027 - Obfuscation
```


### Sysmon-Specific Detection
---

```SPL
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" 
    (EventCode=1 OR EventCode=3 OR EventCode=11)
| rex field=CommandLine "(?i)(?<com_obj>adodb\.stream|msxml2\.domdocument)"
| rex field=CommandLine "(?i)(?<ps_indicator>createelement|bypass|powershell|-nop\s+-w)"
| rex field=CommandLine "(?i)(?<vbs_indicator>createobject|expandenvironmentstrings)"
| where isnotnull(com_obj) OR isnotnull(ps_indicator) OR isnotnull(vbs_indicator)
| stats count by _time, host, user, CommandLine, ParentImage, Image
| where count >= 3
```


### HTA/VBS File Execution Detection
---

```SPL
index=* (sourcetype=WinEventLog:* OR sourcetype=sysmon)
    (process_name="mshta.exe" OR process_name="wscript.exe" OR process_name="cscript.exe")
| eval cmdline_lower=lower(CommandLine)
| search cmdline_lower="*adodb*" OR cmdline_lower="*msxml2*" 
    OR cmdline_lower="*powershell*" OR cmdline_lower="*createobject*"
| eval risk_score=0
| eval risk_score=if(match(cmdline_lower, "adodb\.stream"), risk_score+20, risk_score)
| eval risk_score=if(match(cmdline_lower, "msxml2\.domdocument"), risk_score+20, risk_score)
| eval risk_score=if(match(cmdline_lower, "bypass"), risk_score+15, risk_score)
| eval risk_score=if(match(cmdline_lower, "powershell"), risk_score+15, risk_score)
| eval risk_score=if(match(cmdline_lower, "-nop"), risk_score+15, risk_score)
| eval risk_score=if(match(cmdline_lower, "createobject"), risk_score+10, risk_score)
| where risk_score >= 50
| table _time, host, user, process_name, CommandLine, risk_score, ParentImage
```

### Network IOC Detection
---

```SPL
index=* (sourcetype=pan:traffic OR sourcetype=proxy OR sourcetype=firewall)
| search dest_ip="107.173.47.137" OR url="*wellthingsformebest.js*" OR url="*107.173.47.137*"
| table _time, src_ip, dest_ip, url, action, user
```