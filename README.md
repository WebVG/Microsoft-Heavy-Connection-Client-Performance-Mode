# Microsoft-Heavy-Connection-Client-Performance-Mode
If you are using Connect-Module and running a large job, you likely will benefit from this. This also is meant to run on only Windows and assumes you plan on only running these jobs. Not in the background, not while working. A new pwsh session is opened as admin with higher priority.
- ex. iterating tenant structures for upwards of 1,000 files

### Aggressive process list
- Insta-kills browsers, IDEs, maybe VMs → unsaved work = gone
- Guard rails put in place, not a guarentee it wont do something

### KillExplorer
- Kills your shell; user needs to use Restore (or manually Start-Process explorer.exe) brings it back.

### Stopping services
- Some services are fine to stop (SysMain, WSearch), others can bite. Make sure -StopServices / -StartServices defaults are empty and you explicitly pass what you want.

### Disabling adapters
- You can absolutely cut off your remote session doing this. Avoid doing this over RDP unless you know the network layout.

### Power plan changes
- Safe-ish, but don’t do this on machines with strict power policies (corporate laptops) without checking policy compliance.

## Initial run should be with -whatif parameter
- . .\Invoke-PerfMode.ps1
- Invoke-PerfMode -Mode Boost -Aggressive -KillExplorer -WhatIf


# Usage
- cd into the .ps1 dir
- . .\Invoke-PerfMode.ps1
- Invoke-PerfMode -Mode Boost -Profile MSInfra -SpawnWorkShell
- Invoke-PerfMode -Mode Restore
