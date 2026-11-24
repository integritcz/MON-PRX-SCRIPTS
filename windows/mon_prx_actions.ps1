<#
  MON-PRX-WINDOWS-SERVER actions script (Zabbix agent 2 UserParameters, integrit s.r.o.). PowerShell 5.1+, runs as LocalSystem.
  Separate from mon_prx_windows_server.ps1 on purpose: that script only reads, this one may change something.
  Output: one line of compact JSON (UTF-8). Every change is written to scripts\mon_prx_actions.log.

  -Mode diag    : read-only diagnostics for a ticket: uptime, last Error/Critical events (24 h), top processes, free disk space.
  -Mode recover : starts the services that are STOPPED, set to Automatic start AND listed for THIS host in mon_prx_actions.json.
                  Nothing else can be started: the list is signed (delivered by the MON-PRX script updater), there is no
                  parameter that takes a service name, and each service is started at most 3 times per hour.
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

function Invoke-Recover {
    $res = [ordered]@{ listed = 0; started = @(); failed = @(); skipped = @() }
    if (-not (Test-Path $listF)) { return $res }
    $cfg = Get-Content $listF -Raw | ConvertFrom-Json
    $mine = $cfg.hosts.PSObject.Properties | Where-Object { $_.Name -eq (Get-AgentHostName) } | Select-Object -First 1
    if (-not $mine) { return $res }
    $names = @($mine.Value.recover)
    $res.listed = $names.Count
    $state = @{}
    if (Test-Path $stateF) { try { (Get-Content $stateF -Raw | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $state[$_.Name] = @($_.Value) } } catch { } }
    $cut = (Get-Date).AddHours(-1)
    foreach ($n in $names) {
        $svc = Get-Service -Name $n -ErrorAction SilentlyContinue
        if (-not $svc) { $res.skipped += "$n (not installed)"; continue }
        if ($svc.Status -ne 'Stopped') { continue }
        $start = (Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f ($n -replace "'", ''))).StartMode
        if ($start -ne 'Auto') { $res.skipped += "$n (start type $start)"; continue }
        $recent = @($state[$n] | Where-Object { $_ -and ([datetime]$_) -gt $cut })
        if ($recent.Count -ge 3) { $res.failed += "$n (3 starts in the last hour, giving up)"; Write-Log "GAVE UP $n : started 3 times in the last hour"; continue }
        try {
            Start-Service -Name $n -ErrorAction Stop
            $svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(15))
            $state[$n] = $recent + (Get-Date).ToString('o')
            $res.started += $n
            Write-Log "STARTED $n (was Stopped)"
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
