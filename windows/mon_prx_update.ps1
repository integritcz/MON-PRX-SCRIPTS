<#
  MON-PRX script updater (Windows). Runs daily as a scheduled task (SYSTEM), installed by Install-MON-PRX-Windows-Agent.
  Downloads manifest.json + manifest.sig from the public MON-PRX-SCRIPTS repository, checks the RSA signature with the
  public key built into this script, checks the SHA-256 of every file, and only then replaces this machine's own files.
  Only the files of this machine's profile are touched: mon_prx_<profile>.ps1 / .conf and this updater.
  Anything that fails a check is skipped and logged; the old files stay. Log: scripts\mon_prx_update.log
#>
param(
    [ValidateSet('windows', 'windows_server')][string]$Profile = 'windows',
    [string]$BaseUrl = 'https://raw.githubusercontent.com/integritcz/MON-PRX-SCRIPTS/main',
    # update = check and apply (the scheduled task); run = start the scheduled task and return at once (Zabbix "Execute now");
    # status = JSON with the age of the last successful check and the last log line (Zabbix item).
    [ValidateSet('update', 'run', 'status')][string]$Action = 'update'
)
$ErrorActionPreference = 'Stop'
$dir     = 'C:\Program Files\Zabbix Agent 2'
$scripts = Join-Path $dir 'scripts'
$confDir = Join-Path $dir 'zabbix_agent2.d'
$log     = Join-Path $scripts 'mon_prx_update.log'
$state   = Join-Path $scripts 'mon_prx_update.state'
$PublicKeyXml = '<RSAKeyValue><Modulus>miAusiBpbm3g8ZQ4EPKrdmDg/gQvddpnaUGAAwXov81FPwT3AI/9JyzvW6m4mZ/tULbcXl++EU40RFvaywOsoM/0vjmeLi94944JoVpuJGec2ChtooPFGQj+ctRJcTwrpOhHaiWlws0Az3aNxrLahS4Sssbn/Dqw3PP1I5tW6MNFBCsT0IhnicLAm3PQocgFpdqTPETLpb/LK7laxAT/Ra5Gm4GMq8YBEAsx8DxRmQSW/OlGAEQQqHdHbgkaaNtboCnOZcop9RJMb1QtyZYmAJslOSfYwfZw0dr7X4ryF6J9dgVU7AWrAza1lyqjyc0zSQgZkIY4+5dX7CarsuVSDve24WNCeQk+KfZN1lCsWTVx9RBENGVOGA+IPR139SWvbmv0lLSsYpIlsrRPgBbMfpOn3qnY5RcODl7r+pHQRQEs2g9cyYojaF32azoHLqicIWcL0FQ7XcpE0cjJPMcmqYcDqnzdX6vTul48y4eExhC9t9GohKJrC3xiDD7bDKWr</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>'

if ($Action -eq 'run') {
    try { Start-ScheduledTask -TaskName 'MON-PRX script update' -ErrorAction Stop; 'started' }
    catch { "FAILED to start the task: $($_.Exception.Message)" }
    exit 0
}
if ($Action -eq 'status') {
    $ageH = -1; $gen = ''; $last = ''
    if (Test-Path $state) { $ageH = [math]::Round(((Get-Date) - (Get-Item $state).LastWriteTime).TotalHours, 1); $gen = (Get-Content $state -Raw).Trim() }
    if (Test-Path $log) { $last = (Get-Content $log -Tail 1) }
    [pscustomobject]@{ age_hours = $ageH; manifest = $gen; last_line = $last } | ConvertTo-Json -Compress
    exit 0
}

function Log($m) {
    $line = '{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date), $m
    Add-Content -Path $log -Value $line -Encoding UTF8
    Write-Host $line
}
function Sha256Hex([byte[]]$b) {
    $h = [Security.Cryptography.SHA256]::Create()
    try { return (($h.ComputeHash($b) | ForEach-Object { $_.ToString('x2') }) -join '') } finally { $h.Dispose() }
}
function Get-Bytes($url) {
    $wc = New-Object Net.WebClient
    $wc.Headers.Add('User-Agent', 'MON-PRX-updater')
    $wc.Headers.Add('Cache-Control', 'no-cache')
    try { return $wc.DownloadData($url + '?t=' + [DateTime]::UtcNow.Ticks) } finally { $wc.Dispose() }
}

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if (-not (Test-Path $scripts)) { throw "Missing folder $scripts" }

    $manBytes = Get-Bytes "$BaseUrl/manifest.json"
    $sig = [Convert]::FromBase64String(([Text.Encoding]::ASCII.GetString((Get-Bytes "$BaseUrl/manifest.sig"))).Trim())
    $rsa = New-Object Security.Cryptography.RSACryptoServiceProvider
    $rsa.FromXmlString($PublicKeyXml)
    $okSig = $rsa.VerifyData($manBytes, [Security.Cryptography.CryptoConfig]::MapNameToOID('SHA256'), $sig)
    $rsa.Dispose()
    if (-not $okSig) { throw 'Manifest signature is NOT valid. Nothing was changed.' }

    $man = [Text.Encoding]::UTF8.GetString($manBytes).TrimStart([char]0xFEFF) | ConvertFrom-Json
    # Refuse an older manifest than the one already applied (replay of an old signed version).
    $last = ''
    if (Test-Path $state) { $last = (Get-Content $state -Raw).Trim() }
    if ($last -and $man.generated -lt $last) { throw "Manifest $($man.generated) is older than the applied $last. Nothing was changed." }

    $own = @("windows/mon_prx_$Profile.ps1", "windows/mon_prx_$Profile.conf", 'windows/mon_prx_update.ps1')
    $changed = @(); $confChanged = $false
    foreach ($f in $man.files) {
        if ($own -notcontains $f.path) { continue }
        $name = Split-Path $f.path -Leaf
        $target = if ($name -like '*.conf') { Join-Path $confDir $name } else { Join-Path $scripts $name }
        if ((Test-Path $target) -and ((Sha256Hex ([IO.File]::ReadAllBytes($target))) -eq $f.sha256)) { continue }
        $bytes = Get-Bytes "$BaseUrl/$($f.path)"
        if ((Sha256Hex $bytes) -ne $f.sha256) { Log "SKIPPED $($f.path): checksum does not match the signed manifest"; continue }
        $tmp = "$target.new"
        [IO.File]::WriteAllBytes($tmp, $bytes)
        Move-Item -Path $tmp -Destination $target -Force
        $changed += $name
        if ($name -like '*.conf') { $confChanged = $true }
        Log "UPDATED $name"
    }
    Set-Content -Path $state -Value $man.generated -Encoding ASCII
    if ($confChanged) {
        Restart-Service -Name 'Zabbix Agent 2' -Force
        Log 'Zabbix Agent 2 restarted (the .conf changed)'
    }
    if ($changed.Count -eq 0) { Log "No change (manifest $($man.generated))" }
}
catch {
    Log "FAILED: $($_.Exception.Message)"
    exit 1
}
