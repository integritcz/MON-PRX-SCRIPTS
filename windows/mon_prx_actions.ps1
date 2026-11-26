<#
  MON-PRX-WINDOWS-SERVER actions script (Zabbix agent 2 UserParameters, integrit s.r.o.). PowerShell 5.1+, runs as LocalSystem.
  Separate from mon_prx_windows_server.ps1 on purpose: that script only reads, this one may change something.
  Output: one line of compact JSON (UTF-8). Every change is written to scripts\mon_prx_actions.log.

  -Mode diag    : read-only diagnostics for a ticket: uptime, last Error/Critical events (24 h), top processes, free disk space.
  -Mode recover : starts stopped services. Rule (the same on every server, from the signed mon_prx_actions.json):
                  - every service with start type Automatic (also delayed) that is Stopped, is NOT a trigger-start service
                    (those stop by design) and does not match the shared "exclude" list or the host's own "exclude" list;
                  - plus the services listed for THIS host under "recover" (any start type except Disabled).
                  "auto_all": "report" only lists the Automatic candidates (would_start) without starting them;
                  "on" starts them. The host's "recover" list is always started. Nothing runs in the first 10 minutes
                  after boot, each service is started at most 3 times per hour, and there is no parameter that takes a
                  service name (only the signed list decides).
#>
param(
    [Parameter(Mandatory = $true)][ValidateSet('diag', 'recover')][string]$Mode
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$dir     = 'C:\Program Files\Zabbix Agent 2'
$scripts = Join-Path $dir 'scripts'
$log     = Join-Path $scripts 'mon_prx_actions.log'
$stateF  = Join-Path $scripts 'mon_prx_actions.state'
$listF   = Join-Path $scripts 'mon_prx_actions.json'

function Out-Json($obj) { ConvertTo-Json -InputObject $obj -Compress -Depth 5 }
function Cut($s, $n) { $s = ([string]$s) -replace '\s+', ' '; if ($s.Length -gt $n) { $s.Substring(0, $n) } else { $s } }
function Write-Log($m) {
    if ((Test-Path $log) -and ((Get-Item $log).Length -gt 200KB)) { Move-Item $log "$log.old" -Force }
    Add-Content -Path $log -Value ('{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date), $m) -Encoding UTF8
}
function Get-AgentHostName {
    $t = Get-Content (Join-Path $dir 'zabbix_agent2.conf') -Raw
    if ($t -match '(?im)^\s*Hostname\s*=\s*(\S+)') { return $Matches[1] }
    return ''
}

function Get-Diag {
    $os = Get-CimInstance Win32_OperatingSystem
    $events = @()
    foreach ($logName in 'System', 'Application') {
        try {
            $events += Get-WinEvent -FilterHashtable @{ LogName = $logName; Level = 1, 2; StartTime = (Get-Date).AddHours(-24) } -MaxEvents 10 -ErrorAction Stop
        } catch { }
    }
    $ev = @($events | Sort-Object TimeCreated -Descending | Select-Object -First 12 | ForEach-Object {
        [ordered]@{ time = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm'); log = $_.LogName; source = $_.ProviderName; id = $_.Id; text = (Cut $_.Message 160) }
    })
    $procs = @(Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 5 | ForEach-Object {
        [ordered]@{ name = $_.ProcessName; mem_mb = [int]($_.WorkingSet64 / 1MB); cpu_s = [int]$_.CPU }
    })
    $vols = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
        [ordered]@{ drive = $_.DeviceID; free_gb = [math]::Round($_.FreeSpace / 1GB, 1); size_gb = [math]::Round($_.Size / 1GB, 1) }
    })
    [ordered]@{
        host        = (Get-AgentHostName)
        uptime_days = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 1)
        free_ram_mb = [int]($os.FreePhysicalMemory / 1024)
        events      = $ev
        top_memory  = $procs
        volumes     = $vols
    }
}

function Test-Match([string]$name, $patterns) {
    foreach ($p in @($patterns)) { if ($p -and ($name -like $p)) { return $true } }
    return $false
}

function Invoke-Recover {
    $res = [ordered]@{ mode = 'off'; listed = 0; started = @(); failed = @(); skipped = @(); would_start = @() }
    if (-not (Test-Path $listF)) { return $res }
    $cfg = Get-Content $listF -Raw | ConvertFrom-Json
    $hostName = Get-AgentHostName
    $mine = $cfg.hosts.PSObject.Properties | Where-Object { $_.Name -eq $hostName } | Select-Object -First 1
    $listed  = if ($mine -and $mine.Value.recover) { @($mine.Value.recover) } else { @() }
    $exclude = @($cfg.exclude) + $(if ($mine -and $mine.Value.exclude) { @($mine.Value.exclude) } else { @() })
    $res.mode = if ($cfg.auto_all) { [string]$cfg.auto_all } else { 'off' }
    $res.listed = $listed.Count

    $os = Get-CimInstance Win32_OperatingSystem
    if (((Get-Date) - $os.LastBootUpTime).TotalMinutes -lt 10) { $res.skipped += 'all (server started less than 10 minutes ago)'; return $res }

    # Candidates: listed services (any start type but Disabled) + Automatic ones by the rule.
    $all = @(Get-CimInstance Win32_Service)
    $cand = [ordered]@{}
    foreach ($n in $listed) {
        $s = $all | Where-Object { $_.Name -eq $n } | Select-Object -First 1
        if (-not $s) { $res.skipped += "$n (not installed)"; continue }
        if ($s.State -ne 'Stopped') { continue }
        if ($s.StartMode -eq 'Disabled') { $res.skipped += "$n (disabled)"; continue }
        $cand[$s.Name] = 'listed'
    }
    if ($res.mode -eq 'on' -or $res.mode -eq 'report') {
        foreach ($s in $all) {
            if ($s.StartMode -ne 'Auto' -or $s.State -ne 'Stopped' -or $cand.Contains($s.Name)) { continue }
            if (Test-Path ("HKLM:\SYSTEM\CurrentControlSet\Services\{0}\TriggerInfo" -f $s.Name)) { continue }
            if ((Test-Match $s.Name $exclude) -or (Test-Match $s.DisplayName $exclude)) { continue }
            if ($res.mode -eq 'report') { $res.would_start += $s.Name } else { $cand[$s.Name] = 'auto' }
        }
    }

    $state = @{}
    if (Test-Path $stateF) { try { (Get-Content $stateF -Raw | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $state[$_.Name] = @($_.Value) } } catch { } }
    $cut = (Get-Date).AddHours(-1)
    foreach ($n in @($cand.Keys)) {
        $recent = @($state[$n] | Where-Object { $_ -and ([datetime]$_) -gt $cut })
        if ($recent.Count -ge 3) { $res.failed += "$n (3 starts in the last hour, giving up)"; Write-Log "GAVE UP $n : started 3 times in the last hour"; continue }
        try {
            Start-Service -Name $n -ErrorAction Stop
            (Get-Service -Name $n).WaitForStatus('Running', [TimeSpan]::FromSeconds(15))
            $state[$n] = $recent + (Get-Date).ToString('o')
            $res.started += $n
            Write-Log "STARTED $n (was Stopped, $($cand[$n]))"
        } catch {
            $state[$n] = $recent + (Get-Date).ToString('o')
            $res.failed += ("{0} ({1})" -f $n, (Cut $_.Exception.Message 80))
            Write-Log "FAILED to start $n : $($_.Exception.Message)"
        }
    }
    Set-Content -Path $stateF -Value (Out-Json $state) -Encoding UTF8
    $res
}

switch ($Mode) {
    'diag'    { Out-Json (Get-Diag) }
    'recover' { Out-Json (Invoke-Recover) }
}
