<#! 
.SYNOPSIS
  Combined performance helper: Boost / Restore with profiles, stateful restore, and VM safety.

.DESCRIPTION
  Mode Boost:
    - Checks for VM processes; refuses to run if found (to avoid crashing VMs).
    - Applies a profile (Default/MSInfra/DevBox) unless overridden by parameters.
    - Saves pre-boost state (power plan, services, adapters, Explorer) to JSON.
    - Optionally: stops “non-critical” processes, kills Explorer, stops services, disables adapters.
    - Sets current pwsh priority + affinity.
    - Optionally: spawns a new elevated pwsh as High priority for workloads.

  Mode Restore:
    - Reads the state JSON written by Boost.
    - Restores power plan, services, adapters, and Explorer as they were.
    - Outputs a summary of anything that could NOT be restored (drift).

  ⚠ Aggressive + KillExplorer + many services/adapters triggers a hard "CONFIRM" confirmation.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Boost','Restore')]
    [string]$Mode,

    [ValidateSet('Default','MSInfra','DevBox')]
    [string]$Profile = 'Default',

    # Boost behavior
    [switch]$Aggressive,
    [switch]$KillExplorer,
    [string[]]$StopServices = @(),
    [string[]]$DisableAdapters = @(),
    [ValidateRange(0.1,1.0)] [double]$AffinityFraction = 0.75,
    [ValidateSet('Normal','AboveNormal','High')] [string]$Priority = 'High',
    [switch]$SpawnWorkShell,

    # Paths
    [string]$LogPath = "$env:TEMP\PerfMode.log",
    [string]$StatePath  # optional override, e.g. per-machine
)

# ---------- Logging ----------
function Write-PerfLog {
    param(
        [string]$Message,
        [ValidateSet('Info','Warn','Error','Verbose')] [string]$Level = 'Info'
    )
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "[{0}] [{1}] {2}" -f $ts, $Level.ToUpper(), $Message
    $dir = Split-Path $LogPath -Parent
    if ($dir -and -not (Test-Path $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
    Add-Content -Path $LogPath -Value $line
    if ($Level -eq 'Error') {
        Write-Host $line -ForegroundColor Red
    } elseif ($Level -eq 'Warn') {
        Write-Host $line -ForegroundColor Yellow
    } elseif ($Level -eq 'Verbose') {
        Write-Host $line -ForegroundColor DarkGray
    } else {
        Write-Host $line
    }
}
# region NetBoost HTTP helpers

function New-SharedHttpClient {
    [CmdletBinding()]
    param(
        [int]$MaxConnectionsPerServer = 200,
        [int]$TimeoutSeconds = 120,
        [int]$PooledConnectionLifetimeMinutes = 10,
        [int]$PooledConnectionIdleTimeoutMinutes = 2
    )

    try {
        # Modern handler with connection pooling controls
        $handler = [System.Net.Http.SocketsHttpHandler]::new()
        $handler.MaxConnectionsPerServer     = $MaxConnectionsPerServer
        $handler.PooledConnectionLifetime    = [TimeSpan]::FromMinutes($PooledConnectionLifetimeMinutes)
        $handler.PooledConnectionIdleTimeout = [TimeSpan]::FromMinutes($PooledConnectionIdleTimeoutMinutes)

        $client          = [System.Net.Http.HttpClient]::new($handler)
        $client.Timeout  = [TimeSpan]::FromSeconds($TimeoutSeconds)

        Write-PerfLog "NetBoost: Created HttpClient (MaxConnectionsPerServer=$MaxConnectionsPerServer, Timeout=${TimeoutSeconds}s)" 'Info'
        return $client
    } catch {
        Write-PerfLog "NetBoost: Failed to create HttpClient: $($_.Exception.Message)" 'Error'
        throw
    }
}

function Invoke-HttpWithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [System.Net.Http.HttpClient]$Client,
        [Parameter(Mandatory)] [string]$Uri,
        [ValidateSet('GET','POST','PUT','DELETE','PATCH')]
        [string]$Method = 'GET',
        [hashtable]$Headers,
        [string]$Body,
        [int]$MaxAttempts = 5,
        [int]$BaseDelaySeconds = 2,
        [switch]$ReturnResponseMessage  # if not set, returns string content
    )

    $attempt = 0
    while ($true) {
        $attempt++

        try {
            $req = [System.Net.Http.HttpRequestMessage]::new(
                [System.Net.Http.HttpMethod]::new($Method),
                $Uri
            )

            if ($Headers) {
                foreach ($k in $Headers.Keys) {
                    $null = $req.Headers.TryAddWithoutValidation($k, [string]$Headers[$k])
                }
            }

            if ($Body -and $Method -in @('POST','PUT','PATCH')) {
                $req.Content = [System.Net.Http.StringContent]::new($Body, [Text.Encoding]::UTF8, 'application/json')
            }

            $resp = $Client.SendAsync($req).Result

            if ($resp.IsSuccessStatusCode) {
                if ($ReturnResponseMessage) { return $resp }
                return $resp.Content.ReadAsStringAsync().Result
            }

            # Handle 429/5xx with backoff
            $statusCode = [int]$resp.StatusCode
            $isRetryable =
                ($statusCode -eq 429) -or
                ($statusCode -ge 500 -and $statusCode -lt 600)

            if (-not $isRetryable -or $attempt -ge $MaxAttempts) {
                $msg = "HTTP $statusCode for $Uri after $attempt attempt(s)"
                Write-PerfLog "NetBoost: $msg" 'Error'
                throw $msg
            }

            # Retry-After logic
            $retryDelaySec = $BaseDelaySeconds * [math]::Pow(2, ($attempt - 1))
            if ($resp.Headers.RetryAfter) {
                if ($resp.Headers.RetryAfter.Delta) {
                    $retryDelaySec = [int]$resp.Headers.RetryAfter.Delta.TotalSeconds
                } elseif ($resp.Headers.RetryAfter.Date) {
                    $delta = $resp.Headers.RetryAfter.Date.Value - [DateTimeOffset]::UtcNow
                    if ($delta.TotalSeconds -gt 0) {
                        $retryDelaySec = [int][math]::Ceiling($delta.TotalSeconds)
                    }
                }
            }

            $retryDelaySec = [math]::Min($retryDelaySec, 60)  # cap at 60s
            Write-PerfLog "NetBoost: HTTP $statusCode for $Uri (attempt $attempt). Retrying in ${retryDelaySec}s..." 'Warn'
            Start-Sleep -Seconds $retryDelaySec
        } catch {
            if ($attempt -ge $MaxAttempts) {
                $msg = "NetBoost: giving up on $Uri after $attempt attempt(s): $($_.Exception.Message)"
                Write-PerfLog $msg 'Error'
                throw $msg
            }

            $retryDelaySec = $BaseDelaySeconds * [math]::Pow(2, ($attempt - 1))
            $retryDelaySec = [math]::Min($retryDelaySec, 60)
            Write-PerfLog "NetBoost: exception on attempt $attempt for $Uri $($_.Exception.Message). Retrying in ${retryDelaySec}s..." 'Warn'
            Start-Sleep -Seconds $retryDelaySec
        }
    }
}

function Initialize-NetBoost {
    [CmdletBinding()]
    param(
        [int]$MaxConnectionsPerServer = 200,
        [int]$TimeoutSeconds = 120
    )

    # Raise process-wide default connection limit for classic HttpWebRequest users too
    [System.Net.ServicePointManager]::DefaultConnectionLimit = $MaxConnectionsPerServer

    $client = New-SharedHttpClient -MaxConnectionsPerServer $MaxConnectionsPerServer `
                                   -TimeoutSeconds $TimeoutSeconds

    # Make the client easy to reach for your session
    $Global:NetBoostClient = $client

    Write-PerfLog "NetBoost: initialized shared HttpClient in `$Global:NetBoostClient." 'Info'
    Write-PerfLog "NetBoost: use Invoke-HttpWithRetry -Client `$Global:NetBoostClient -Uri ... for Graph/M365 calls." 'Verbose'
}

# endregion


# ---------- Admin check ----------
function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must be run elevated (as Administrator)."
    }
}
Assert-Admin

# ---------- State file ----------
$stateRoot = if ($StatePath) {
    Split-Path $StatePath -Parent
} else {
    Join-Path $env:LOCALAPPDATA "PerfMode"
}

if (-not (Test-Path $stateRoot)) {
    New-Item -ItemType Directory -Force -Path $stateRoot | Out-Null
}
$stateFile = if ($StatePath) { $StatePath } else { Join-Path $stateRoot "PerfModeState.json" }

# ---------- Helpers: power plan ----------
function Get-ActivePowerPlanGuid {
    $output = powercfg /GETACTIVESCHEME 2>$null
    if ($output -match 'GUID:\s*([0-9a-fA-F\-]+)') {
        return $matches[1]
    }
    return $null
}

function Set-PowerPlanByGuid {
    param([string]$Guid)
    if (-not $Guid) { return }
    try {
        if ($PSCmdlet.ShouldProcess("Power plan $Guid","Set active")) {
            powercfg -S $Guid | Out-Null
            Write-PerfLog "Switched power plan to $Guid"
        }
    } catch {
        Write-PerfLog -Message "Failed to switch power plan to $Guid $($_.Exception.Message)" -Level 'Error'
    }
}

# ---------- Helpers: process priority/affinity ----------
function Set-CurrentProcessPriorityAndAffinity {
    param(
        [ValidateSet('Normal','AboveNormal','High')]
        [string]$PriorityClass = 'High',
        [ValidateRange(0.1,1.0)]
        [double]$Fraction = 0.75
    )
    try {
        $p = Get-Process -Id $PID -ErrorAction Stop
        Write-PerfLog "Setting pwsh (PID=$($p.Id)) priority to $PriorityClass"
        if ($PSCmdlet.ShouldProcess("pwsh PID=$($p.Id)", "Set Priority $PriorityClass")) {
            $p.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::$PriorityClass
        }

        $logical = [Environment]::ProcessorCount
        $use     = [Math]::Max(1, [Math]::Floor($logical * $Fraction))
        if ($use -lt $logical) {
            $mask = 0
            for ($i = 0; $i -lt $use; $i++) { $mask = $mask -bor (1 -shl $i) }
            Write-PerfLog "Setting CPU affinity to $use/$logical logical CPUs"
            if ($PSCmdlet.ShouldProcess("pwsh PID=$($p.Id)", "Set Affinity $use cores")) {
                $p.ProcessorAffinity = [IntPtr]$mask
            }
        } else {
            Write-PerfLog "Using all $logical logical CPUs; no affinity mask."
        }
    } catch {
        Write-PerfLog "Failed to set priority/affinity: $($_.Exception.Message)" 'Error'
    }
}

# ---------- Helpers: profiles ----------
$profileMap = @{
    'Default' = @{
        Aggressive      = $false
        KillExplorer    = $false
        StopServices    = @()
        DisableAdapters = @()
    }
    'MSInfra' = @{
        Aggressive      = $false
        KillExplorer    = $false
        StopServices    = @('WSearch','SysMain')
        DisableAdapters = @('Wi-Fi')
    }
    'DevBox' = @{
        Aggressive      = $true
        KillExplorer    = $false
        StopServices    = @('WSearch')
        DisableAdapters = @()
    }
}

function Resolve-EffectiveSettings {
    param(
        [string]$Profile,
        [switch]$Aggressive,
        [switch]$KillExplorer,
        [string[]]$StopServices,
        [string[]]$DisableAdapters
    )

    $cfg = $profileMap[$Profile]
    if (-not $cfg) { $cfg = $profileMap['Default'] }

    # Explicit parameters override profile
    $effectiveAggressive = if ($PSBoundParameters.ContainsKey('Aggressive')) { [bool]$Aggressive } else { [bool]$cfg.Aggressive }
    $effectiveKillExp    = if ($PSBoundParameters.ContainsKey('KillExplorer')) { [bool]$KillExplorer } else { [bool]$cfg.KillExplorer }
    $effectiveStopSvc    = if ($PSBoundParameters.ContainsKey('StopServices')) { $StopServices } else { [string[]]$cfg.StopServices }
    $effectiveDisAdapters= if ($PSBoundParameters.ContainsKey('DisableAdapters')) { $DisableAdapters } else { [string[]]$cfg.DisableAdapters }

    [pscustomobject]@{
        Aggressive      = $effectiveAggressive
        KillExplorer    = $effectiveKillExp
        StopServices    = $effectiveStopSvc
        DisableAdapters = $effectiveDisAdapters
    }
}

# ---------- Helpers: VM safety ----------
function Test-VirtualizationRisk {
    $vmNames = @(
        'vmware','vmware-vmx',
        'VirtualBoxVM','vboxservice','vboxtray',
        'vmmem','vmwp',
        'qemu-system'
    )
    $running = Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $name = $_.ProcessName
        $vmNames -contains $name -or $name -like 'qemu-system*'
    }
    return ($running.Count -gt 0)
}

# ---------- Helpers: process trimming (virtualization excluded) ----------
function Stop-NonCriticalProcesses {
    param(
        [switch]$Aggressive,
        [switch]$KillExplorer
    )

	$whitelist = @(
		'System','Idle','smss','csrss','wininit','services','lsass','svchost','winlogon','fontdrvhost','dwm','sihost',
		'ShellExperienceHost','StartMenuExperienceHost','TextInputHost',
		'taskmgr','explorer',
		'conhost','cmd','powershell','pwsh','WindowsTerminal','OpenConsole','mstsc','rdpclip',
		'Alacritty','WezTerm','ConEmu64','ConEmu'
	)


    # Base heavy user apps
    $baseBlock = @(
        'chrome','msedge','firefox','opera','vivaldi','brave',
        'outlook','teams','ms-teams','lync','slack','zoom','discord','webex',
        'onedrive','dropbox','box','googledrivefs','steam','epicgameslauncher',
        'spotify','itunes','whatsapp','signal','telegram',
        'code','vscode','devenv','pycharm','idea64','studio64',
        'docker','docker desktop','wsl','wslhost'
        # NOTE: intentionally NOT including vmware/VirtualBox/etc to avoid killing VMs
    )

    $extraAggressive = @(
        'git','githubdesktop','adb','node','npm','yarn','go','kubectl','minikube','terraform','az','aws',
        'postman','insomnia','obs64','obs','nvidia share','geforce experience'
    )

    $blockList = $baseBlock
    if ($Aggressive) { $blockList += $extraAggressive }

    $all = Get-Process -ErrorAction SilentlyContinue
    foreach ($p in $all) {
        $name = $p.ProcessName
        if ($whitelist -contains $name) { continue }
        if ($blockList -notcontains $name) { continue }

        if ($PSCmdlet.ShouldProcess("Process $name ($($p.Id))","Stop")) {
            try {
                Write-PerfLog "Stopping process $name ($($p.Id))"
                if ($p.MainWindowHandle -and -not [string]::IsNullOrWhiteSpace($p.MainWindowTitle)) {
                    $p.CloseMainWindow() | Out-Null
                    Start-Sleep -Milliseconds 300
                }
                if (-not $p.HasExited) { $p.Kill() }
            } catch {
                Write-PerfLog -Message "Failed to stop $name $($_.Exception.Message)" -Level 'Warn'
            }
        }
    }

    if ($KillExplorer) {
        $exp = Get-Process -Name explorer -ErrorAction SilentlyContinue
        foreach ($p in $exp) {
            if ($PSCmdlet.ShouldProcess("explorer.exe ($($p.Id))","Kill")) {
                Write-PerfLog "Killing explorer.exe ($($p.Id))"
                $p.Kill()
            }
        }
    }
}

# ---------- Helpers: services / adapters ----------
function Stop-SelectedServices {
    param([string[]]$Names, [ref]$Snapshot)

    foreach ($name in $Names) {
        try {
            $svc = Get-Service -Name $name -ErrorAction Stop
        } catch {
            Write-PerfLog "Service '$name' not found: $($_.Exception.Message)" 'Warn'
            continue
        }
        # Record original state
        $Snapshot.Value += [pscustomobject]@{
            Name       = $svc.ServiceName
            WasRunning = ($svc.Status -eq 'Running')
        }
        if ($svc.Status -eq 'Running' -and $PSCmdlet.ShouldProcess("Service $name","Stop")) {
            Write-PerfLog "Stopping service: $name"
            Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
        }
    }
}

function Disable-NetworkAdaptersWithSnapshot {
    param([string[]]$Names, [ref]$Snapshot)

    foreach ($pattern in $Names) {
        $adapters = Get-NetAdapter -Name $pattern -ErrorAction SilentlyContinue
        if (-not $adapters) {
            $adapters = Get-NetAdapter | Where-Object { $_.Name -like "*$pattern*" }
        }
        foreach ($a in $adapters) {
            # Record original status
            $Snapshot.Value += [pscustomobject]@{
                Name         = $a.Name
                StatusBefore = $a.Status
            }
            if ($a.Status -ne 'Disabled' -and $PSCmdlet.ShouldProcess("Adapter $($a.Name)","Disable")) {
                Write-PerfLog "Disabling adapter: $($a.Name)"
                Disable-NetAdapter -Name $a.Name -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
    }
}

function Enable-NetworkAdaptersFromSnapshot {
    param([object[]]$Snapshots, [ref]$NotReverted)

    foreach ($snap in $Snapshots) {
        try {
            $a = Get-NetAdapter -Name $snap.Name -ErrorAction Stop
        } catch {
            Write-PerfLog "Adapter '$($snap.Name)' not found during restore." 'Warn'
            $NotReverted.Value += "Adapter '$($snap.Name)' missing"
            continue
        }
        if ($snap.StatusBefore -eq 'Up' -and $a.Status -ne 'Up') {
            Write-PerfLog "Re-enabling adapter: $($a.Name)"
            Enable-NetAdapter -Name $a.Name -Confirm:$false -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1
            $a = Get-NetAdapter -Name $snap.Name -ErrorAction SilentlyContinue
            if ($a.Status -ne 'Up') {
                $NotReverted.Value += "Adapter '$($snap.Name)' not back to 'Up'"
            }
        }
    }
}

function Start-ServicesFromSnapshot {
    param([object[]]$Snapshots, [ref]$NotReverted)

    foreach ($snap in $Snapshots) {
        if (-not $snap.WasRunning) { continue }
        try {
            $svc = Get-Service -Name $snap.Name -ErrorAction Stop
        } catch {
            Write-PerfLog "Service '$($snap.Name)' not found during restore." 'Warn'
            $NotReverted.Value += "Service '$($snap.Name)' missing"
            continue
        }
        if ($svc.Status -ne 'Running') {
            Write-PerfLog "Starting service: $($snap.Name)"
            Start-Service -Name $snap.Name -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1
            $svc = Get-Service -Name $snap.Name -ErrorAction SilentlyContinue
            if ($svc.Status -ne 'Running') {
                $NotReverted.Value += "Service '$($snap.Name)' still not running"
            }
        }
    }
}

# ---------- Helpers: Explorer ----------
function Start-ExplorerIfNeeded {
    if (Get-Process -Name explorer -ErrorAction SilentlyContinue) {
        return
    }
    if ($PSCmdlet.ShouldProcess("explorer.exe","Start")) {
        Write-PerfLog "Starting explorer.exe"
        Start-Process explorer.exe | Out-Null
    }
}

# ---------- Hard guard ----------
function Invoke-HardGuardCheck {
    param(
        [bool]$Aggressive,
        [bool]$KillExplorer,
        [int]$ImpactCount
    )

    if ($Aggressive -and $KillExplorer -and $ImpactCount -ge 3) {
        Write-PerfLog "HIGH IMPACT: Aggressive + KillExplorer + many services/adapters." 'Warn'
        $confirm = Read-Host "Type CONFIRM to proceed *case-sensitive*"
        if ($confirm -ne 'CONFIRM') {
            throw "User declined high-impact boost. Aborting."
        }
    }
}

# ---------- Work shell ----------
function Spawn-WorkloadShell {
    Write-PerfLog "Spawning a high-priority elevated pwsh workload shell..."
    $cmd = '[System.Diagnostics.Process]::GetCurrentProcess().PriorityClass="High"; Write-Host "High-priority workload shell ready." -ForegroundColor Green;'
    $args = @(
        '-NoLogo','-NoProfile','-ExecutionPolicy','Bypass',
        '-Command', $cmd
    )
    if ($PSCmdlet.ShouldProcess('pwsh', 'Start workload shell')) {
        Start-Process -FilePath 'pwsh' -Verb RunAs -ArgumentList $args | Out-Null
    }
}

# ==================== MAIN ====================

if ($Mode -eq 'Boost') {

    # VM safety
    if (Test-VirtualizationRisk) {
        Write-PerfLog "Virtualization-related processes detected. Refusing to run Boost to avoid crashing VMs." 'Error'
        return
    }

    $eff = Resolve-EffectiveSettings -Profile $Profile -Aggressive:$Aggressive -KillExplorer:$KillExplorer `
        -StopServices $StopServices -DisableAdapters $DisableAdapters

    Write-PerfLog "Effective settings: Profile=$Profile Aggressive=$($eff.Aggressive) KillExplorer=$($eff.KillExplorer) StopServices=$($eff.StopServices -join ';') DisableAdapters=$($eff.DisableAdapters -join ';')"
	if ($Profile -eq 'MSInfra') {
		Write-PerfLog "Profile MSInfra: initializing NetBoost HttpClient tuning." 'Info'
		Initialize-NetBoost -MaxConnectionsPerServer 200 -TimeoutSeconds 120
	}

    $impactCount = $eff.StopServices.Count + $eff.DisableAdapters.Count
    Invoke-HardGuardCheck -Aggressive:$eff.Aggressive -KillExplorer:$eff.KillExplorer -ImpactCount $impactCount

    # Capture pre-boost state
    $originalPlan = Get-ActivePowerPlanGuid
    $explorerWasRunning = (Get-Process -Name explorer -ErrorAction SilentlyContinue) -ne $null
    $svcSnapshot = New-Object System.Collections.Generic.List[object]
    $adapterSnapshot = New-Object System.Collections.Generic.List[object]

    # Apply
    Write-PerfLog "Boost: capturing state and applying performance tweaks..."
    Set-CurrentProcessPriorityAndAffinity -PriorityClass $Priority -Fraction $AffinityFraction
    Stop-NonCriticalProcesses -Aggressive:$eff.Aggressive -KillExplorer:$eff.KillExplorer
    if ($eff.StopServices.Count -gt 0) {
        Stop-SelectedServices -Names $eff.StopServices -Snapshot ([ref]$svcSnapshot)
    }
    if ($eff.DisableAdapters.Count -gt 0) {
        Disable-NetworkAdaptersWithSnapshot -Names $eff.DisableAdapters -Snapshot ([ref]$adapterSnapshot)
    }

    # Persist state
    $state = [pscustomobject]@{
        TimestampUtc         = (Get-Date).ToUniversalTime().ToString("o")
        Mode                 = 'Boost'
        Profile              = $Profile
        OriginalPowerPlanGuid= $originalPlan
        ExplorerWasRunning   = $explorerWasRunning
        Services             = $svcSnapshot
        Adapters             = $adapterSnapshot
    }
    $state | ConvertTo-Json -Depth 5 | Set-Content -Path $stateFile -Encoding UTF8
    Write-PerfLog "Saved boost state to $stateFile"

    if ($SpawnWorkShell) {
        Spawn-WorkloadShell
    }

    Write-PerfLog "Boost complete. Run your workload now in this session or the spawned shell."

} elseif ($Mode -eq 'Restore') {

    if (-not (Test-Path $stateFile)) {
        Write-PerfLog "No state file found at $stateFile. Nothing to restore." 'Warn'
        return
    }

    $json = Get-Content -Path $stateFile -Raw | ConvertFrom-Json
    Write-PerfLog "Restoring from state captured at $($json.TimestampUtc) (Profile=$($json.Profile))"

    $notReverted = New-Object System.Collections.Generic.List[string]

    # Power plan
    if ($json.OriginalPowerPlanGuid) {
        $currentGuid = Get-ActivePowerPlanGuid
        if ($currentGuid -ne $json.OriginalPowerPlanGuid) {
            Set-PowerPlanByGuid -Guid $json.OriginalPowerPlanGuid
            $afterGuid = Get-ActivePowerPlanGuid
            if ($afterGuid -ne $json.OriginalPowerPlanGuid) {
                $notReverted.Add("Power plan not reverted to $($json.OriginalPowerPlanGuid)")
            }
        }
    }

    # Services
    if ($json.Services) {
        Start-ServicesFromSnapshot -Snapshots $json.Services -NotReverted ([ref]$notReverted)
    }

    # Adapters
    if ($json.Adapters) {
        Enable-NetworkAdaptersFromSnapshot -Snapshots $json.Adapters -NotReverted ([ref]$notReverted)
    }

    # Explorer
    if ($json.ExplorerWasRunning) {
        if (-not (Get-Process -Name explorer -ErrorAction SilentlyContinue)) {
            Start-ExplorerIfNeeded
            Start-Sleep -Seconds 1
            if (-not (Get-Process -Name explorer -ErrorAction SilentlyContinue)) {
                $notReverted.Add("Explorer was running before but could not be started.")
            }
        }
    }

    Write-PerfLog "Restore phase complete."

    if ($notReverted.Count -gt 0) {
        Write-Host "The following items could NOT be fully reverted:" -ForegroundColor Yellow
        $notReverted | ForEach-Object { Write-Host " - $_" -ForegroundColor Yellow }
    } else {
        Write-Host "All tracked settings were restored successfully." -ForegroundColor Green
    }
}
