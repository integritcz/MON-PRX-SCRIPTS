<#
  MON-PRX-WINDOWS-SERVER agent script for Windows Server (Zabbix agent 2 UserParameters, integrit s.r.o.).
  Runs as the agent service account (LocalSystem). Read-only. PowerShell 5.1+.
  Output: one line of compact JSON (UTF-8).

  -Mode updates : pending updates from the last Windows Update scan stored on the machine (offline search, fast),
                  reboot flag, days since last installed update
  -Mode tasks   : enabled scheduled tasks outside \Microsoft\ with last result and time since last run
  -Mode time    : w32tm source, synchronised flag, offset to source (or to -Ref host)
  -Mode hyperv  : Hyper-V virtual machines of this host with state (empty list [] when Hyper-V is not installed)
#>
param(
    [Parameter(Mandatory = $true)][ValidateSet('updates', 'tasks', 'time', 'hyperv')][string]$Mode,
    [string]$Ref = ''
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8

function Out-Json($obj) {
    ConvertTo-Json -InputObject $obj -Compress -Depth 4
}

function Get-UpdateStatus {
    # Classification IDs are language independent.
    $secClass = @('0fa1201d-4330-4fa8-8ae9-b877473b6441',  # Security Updates
                  'e6cf1350-c01b-414d-a61f-263d14d133b4')  # Critical Updates
    # Defender definitions/platform and MSRT install daily/monthly and must not count as "patched".
    $ignoreKb = 'KB2267602|KB4052623|KB2310138|KB915597'

    $session  = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    # Offline search = the result of the last scan Windows made itself. Fast (no network, no 30 s limit problem).
    $searcher.Online = $false
    $result = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")

    $now = Get-Date
    $total = 0; $security = 0; $oldest = 0
    foreach ($u in $result.Updates) {
        $total++
        $isSec = $false
        foreach ($c in $u.Categories) {
            if ($secClass -contains $c.CategoryID.ToLower()) { $isSec = $true }
        }
        if ($isSec) {
            $security++
            $age = [int][math]::Floor(($now - $u.LastDeploymentChangeTime).TotalDays)
            if ($age -gt $oldest) { $oldest = $age }
        }
    }

    $lastInstall = $null
    $count = $searcher.GetTotalHistoryCount()
    if ($count -gt 0) {
        foreach ($h in $searcher.QueryHistory(0, $count)) {
            # Operation 1 = installation, ResultCode 2 = succeeded / 3 = succeeded with errors
            if ($h.Operation -eq 1 -and ($h.ResultCode -eq 2 -or $h.ResultCode -eq 3) -and $h.Title -notmatch $ignoreKb) {
                if ($null -eq $lastInstall -or $h.Date -gt $lastInstall) { $lastInstall = $h.Date }
            }
        }
    }
    if ($null -eq $lastInstall) {
        $hf = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
        if ($hf) { $lastInstall = $hf.InstalledOn.ToUniversalTime() }
    }
    # History dates are UTC.
    $lastDays = if ($lastInstall) { [int][math]::Floor(((Get-Date).ToUniversalTime() - $lastInstall).TotalDays) } else { 9999 }
    if ($lastDays -lt 0) { $lastDays = 0 }

    $reboot = 0
    if ((New-Object -ComObject Microsoft.Update.SystemInfo).RebootRequired) { $reboot = 1 }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reboot = 1 }

    [ordered]@{
        total                = $total
        security             = $security
        security_oldest_days = $oldest
        reboot_required      = $reboot
        last_patch_days      = $lastDays
    }
}

function Get-TaskStatus {
    $now = Get-Date
    $list = @()
    foreach ($t in (Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' })) {
        $info = $t | Get-ScheduledTaskInfo
        # Never-run tasks report LastRunTime 1999-11-30 or empty.
        $age = -1
        if ($info.LastRunTime -and $info.LastRunTime.Year -ge 2000) {
            $age = [int][math]::Floor(($now - $info.LastRunTime).TotalSeconds)
        }
        $list += [ordered]@{
            key          = (($t.TaskPath + $t.TaskName) -replace '[^A-Za-z0-9._-]', '_')
            path         = $t.TaskPath
            name         = $t.TaskName
            state        = [string]$t.State
            last_result  = [uint32]$info.LastTaskResult
            last_run_age = $age
        }
    }
    , $list
}

function Get-TimeStatus([string]$ref) {
    $source = ((& w32tm /query /source) | Out-String).Trim() -replace ',0x[0-9a-fA-F]+$', ''
    $synced = 1
    # w32tm failed (e.g. Windows Time service stopped): report not synchronised, not the error text as source.
    if ($LASTEXITCODE -ne 0 -or $source -match 'error occurred|0x[0-9a-fA-F]{8}') { $source = 'unavailable'; $synced = 0 }
    if ($source -match 'Local CMOS Clock|Free-running System Clock') { $synced = 0 }

    $target = $ref
    if (-not $target -and $synced -eq 1 -and $source -notmatch 'VM IC Time Synchronization Provider') { $target = $source }

    $offset = $null
    if ($target) {
        $out = & w32tm /stripchart /computer:$target /samples:1 /dataonly 2>&1
        foreach ($line in $out) {
            if ("$line" -match '([+-]\d+[.,]\d+)s\s*$') {
                $offset = [double]::Parse(($Matches[1] -replace ',', '.'), [Globalization.CultureInfo]::InvariantCulture)
            }
        }
    }
    $o = [ordered]@{ source = $source; synced = $synced }
    # Offset only when it could be measured, so the item stays empty instead of failing.
    if ($null -ne $offset) { $o['offset'] = $offset }
    $o
}

function Get-HyperVStatus {
    # WMI of the Hyper-V role (no PowerShell module needed). No Hyper-V role = namespace missing = empty list, not an error.
    $list = @()
    try {
        $vms = Get-CimInstance -Namespace 'root\virtualization\v2' -ClassName Msvm_ComputerSystem -Filter "Caption='Virtual Machine'" -ErrorAction Stop
    } catch {
        $vms = @()
    }
    foreach ($v in $vms) {
        $list += [ordered]@{
            key    = [string]$v.Name
            name   = [string]$v.ElementName
            state  = [int]$v.EnabledState
            health = [int]$v.HealthState
        }
    }
    , $list
}

switch ($Mode) {
    'updates' { Out-Json (Get-UpdateStatus) }
    'tasks'   { Out-Json (Get-TaskStatus) }
    'time'    { Out-Json (Get-TimeStatus $Ref) }
    'hyperv'  { Out-Json (Get-HyperVStatus) }
}
