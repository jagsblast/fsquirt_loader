copy the fsquirt binary to somewhere you can write to, then drop the bthprops.cpl file in the same dir and launch fsquirt

Powershell copy command:
```Copy-Item "C:\Windows\System32\fsquirt.exe" .```

command to compile main.c from kali:
```x86_64-w64-mingw32-gcc -shared -Os -s -o bthprops.cpl main.c -luser32 -lwininet```

Tested working against Windows defender, CrowdStrike, SentinelOne 




Falcon Detection strat
```
Fsquirt.exe lolbin abuse -
 
When this rule fires, there is a high likelihood that a malicious bthprops.cpl file has been dropped to proxy code execution. This technique abuses fsquirt.exe, which will load an arbitrary bthprops.cpl file from its current working directory, enabling DLL search-order hijacking–style execution.
 
in(#event_simpleName, values=["FileCreateInfo", "NewExecutableWritten", "PeFileWritten"])
| Filename="bthprops.cpl"
 
 
 
weaponized example https://github.com/jagsblast/fsquirt_loader
```
 S1 variant 
```
(event.type='File Modification' OR event.type='File Creation') AND tgt.file.name contains 'bthprops.cpl' src.process.cmdline != 'C:\\WINDOWS\\system32\\svchost.exe -k wsappx -p -s AppXSvc'
```

KQL hunt
```
DeviceFileEvents
| where ActionType in ("FileCreated", "FileModified")
| where
    FileName =~ "bthprops.cpl"
    or (
        FileName =~ "fsquirt.exe"
        and FolderPath !startswith @"C:\Windows\System32"
    )
| project
    DeviceName,
    ActionType,
    FolderPath,
    FileName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    SHA256
| order by TimeGenerated desc
```
