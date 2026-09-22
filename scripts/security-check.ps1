$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$envFile = Join-Path $root '.env'
$script:failed = $false

function Get-EnvValue([string]$key) {
    $line = Select-String -Path $envFile -Pattern "^$key=" | Select-Object -First 1
    if (-not $line) { throw "Missing $key in .env" }
    return $line.Line.Substring($line.Line.IndexOf('=') + 1).Trim('"', ' ')
}
function Ok($m)   { Write-Host "  OK   $m" -ForegroundColor Green }
function Warn($m) { Write-Host "  WARN $m" -ForegroundColor Yellow; $script:failed = $true }
function Fail($m) { Write-Host "  FAIL $m" -ForegroundColor Red; $script:failed = $true }
function Info($m) { Write-Host "  --   $m" }
function GitOutput([string[]]$gitArgs) {
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { return (& git @gitArgs 2>$null) } finally { $ErrorActionPreference = $prev }
}
function IsTracked([string]$path) {
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { & git ls-files --error-unmatch $path 2>$null | Out-Null; return ($LASTEXITCODE -eq 0) }
    finally { $ErrorActionPreference = $prev }
}

$secretNames = @('ADMIN_PASSWORD', 'ADMIN_RESET_TOKEN', 'USER_PASSWORD', 'USER_RESET_PASSWORD', 'USER_RESET_CODE', 'USER_JWT_TOKEN')
$secrets = @{}
foreach ($n in $secretNames) { $secrets[$n] = Get-EnvValue $n }

Push-Location $root
try {
    Write-Host "`n[3] .gitignore / git tracking"
    $gi = Get-Content (Join-Path $root '.gitignore') -Raw
    if ($gi -match '(?m)^\.env\s*$') { Ok ".env is listed in .gitignore" } else { Fail ".env is NOT in .gitignore" }
    if (-not (IsTracked '.env'))     { Ok ".env is NOT tracked by git" }     else { Fail ".env IS tracked by git" }
    if (-not (IsTracked 'api.http')) { Ok "api.http is NOT tracked by git" } else { Fail "api.http IS tracked by git" }
    if (IsTracked '.env.simple')     { Info ".env.simple is tracked (expected: template with empty values)" }
    if (IsTracked 'api.http.simple') { Info "api.http.simple is tracked (must contain only {{VAR}} placeholders)" }

    Write-Host "`n[1][4][5] hardcoded secret scan in working tree (excludes .env itself)"
    $files = Get-ChildItem -Path $root -Recurse -File -Force |
        Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\data\\' -and $_.Name -ne '.env' }
    foreach ($n in $secretNames) {
        $leaks = @()
        foreach ($f in $files) {
            try { $c = Get-Content -Raw -LiteralPath $f.FullName -ErrorAction Stop } catch { continue }
            if ($c -and $c.Contains($secrets[$n])) { $leaks += $f.FullName.Substring($root.Length + 1) }
        }
        if ($leaks.Count -gt 0) { Fail "$n hardcoded in working tree: $($leaks -join ', ')" } else { Ok "$n not hardcoded outside .env" }
    }
    $apiHttp = Get-Content -Raw (Join-Path $root 'api.http')
    foreach ($v in @('{{ADMIN_EMAIL}}', '{{ADMIN_PASSWORD}}', '{{USER_EMAIL}}', '{{USER_PASSWORD}}', '{{ADMIN_RESET_TOKEN}}', '{{USER_RESET_CODE}}', '{{USER_JWT_TOKEN}}')) {
        if ($apiHttp.Contains($v)) { Ok "api.http uses $v" } else { Fail "api.http missing $v" }
    }

    Write-Host "`n[2] git history scan (all commits) - filenames only, no values"
    foreach ($n in $secretNames) {
        $found = @()
        foreach ($c in (GitOutput @('log', '--all', '--format=%h', '-S', $secrets[$n]))) {
            $paths = GitOutput @('grep', '-l', '-F', $secrets[$n], $c)
            if ($paths) { $found += "$c ($($paths -join ', '))" }
        }
        if ($found.Count -gt 0) { Fail "$n present in history: $($found -join ' | ')" } else { Ok "$n never committed" }
    }

    Write-Host "`n[2b] current tips scan (HEAD + remote branches) - filenames only"
    $tips = @('HEAD') + (GitOutput @('for-each-ref', '--format=%(refname:short)', 'refs/remotes'))
    foreach ($b in $tips) {
        foreach ($n in $secretNames) {
            $hits = GitOutput @('grep', '-l', '-F', $secrets[$n], $b)
            if ($hits) { Fail "$n exposed at tip $b -> $($hits -join ', ')" }
        }
    }
    if (-not $script:failed) { Ok "no secret at any current tip" }

    Write-Host "`n[7] database password storage (admin_users)"
    $sql = 'SELECT count(*) AS total, count(*) FILTER (WHERE password ~ ''^\$2[aby]\$'') AS bcrypt_rows, max(length(password)) AS max_len FROM admin_users;'
    $row = ($sql | docker exec -i 69-s2-db psql -U wannipa -d wannipa -t -A) -split '\|'
    $total = [int]$row[0]; $bcrypt = [int]$row[1]; $maxlen = [int]$row[2]
    if ($total -ge 1 -and $total -eq $bcrypt -and $maxlen -eq 60) { Ok "all $total admin password(s) are bcrypt hashes (len 60), no plaintext" }
    else { Fail "admin password storage unexpected (total=$total bcrypt=$bcrypt maxlen=$maxlen)" }

    Write-Host "`n[6] secret scan of container logs"
    $logs = docker logs 69-s2-app 2>&1 | Out-String
    foreach ($n in $secretNames) {
        if ($logs.Contains($secrets[$n])) { Fail "$n leaked in container logs" } else { Ok "$n not present in container logs" }
    }
}
finally { Pop-Location }

Write-Host ""
if ($script:failed) { Write-Host "SECURITY CHECK: ISSUES FOUND" -ForegroundColor Red; exit 1 }
else { Write-Host "SECURITY CHECK: PASSED" -ForegroundColor Green }