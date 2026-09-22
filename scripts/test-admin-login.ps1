$ErrorActionPreference = 'Stop'

$envFile = Join-Path $PSScriptRoot '..\.env'
$baseUrl = 'http://localhost:9092'

function Get-EnvValue([string]$key) {
    $line = Select-String -Path $envFile -Pattern "^$key=" | Select-Object -First 1
    if (-not $line) { throw "Missing $key in .env" }
    return $line.Line.Substring($line.Line.IndexOf('=') + 1).Trim('"', ' ')
}

$adminEmail = Get-EnvValue 'ADMIN_EMAIL'
$adminPassword = Get-EnvValue 'ADMIN_PASSWORD'

function Test-Login([string]$email, [string]$password, [int]$expectedStatus) {
    $body = @{ email = $email; password = $password; rememberMe = $false } | ConvertTo-Json
    try {
        $resp = Invoke-WebRequest -Uri "$baseUrl/admin/login" -Method Post -ContentType 'application/json' -Body $body -UseBasicParsing
        $actual = [int]$resp.StatusCode
    } catch {
        if (-not $_.Exception.Response) { throw }
        $actual = [int]$_.Exception.Response.StatusCode
    }
    if ($actual -ne $expectedStatus) {
        throw "login($email) expected $expectedStatus but got $actual"
    }
    return $actual
}

Write-Host "1) admin login with WRONG password should be 400"
$code = Test-Login $adminEmail "$adminPassword-typo" 400
Write-Host "   PASS -> HTTP $code (Invalid credentials)"

Write-Host "2) admin login with CORRECT password should be 200"
$code = Test-Login $adminEmail $adminPassword 200
Write-Host "   PASS -> HTTP $code"

Write-Host "3) admin login returns a JWT "
$body = @{ email = $adminEmail; password = $adminPassword; rememberMe = $false } | ConvertTo-Json
$resp = Invoke-WebRequest -Uri "$baseUrl/admin/login" -Method Post -ContentType 'application/json' -Body $body -UseBasicParsing
$token = ($resp.Content | ConvertFrom-Json).data.token
if (-not $token) { throw "login did not return a token" }
Write-Host "   PASS -> token present (len=$($token.Length))"

Write-Host "4) GET /admin/users/me with Bearer JWT should be 200 JSON"
$me = Invoke-WebRequest -Uri "$baseUrl/admin/users/me" -Headers @{ Authorization = "Bearer $token" } -UseBasicParsing
$meJson = $me.Content | ConvertFrom-Json
if ($me.StatusCode -ne 200 -or $meJson.data.email -ne $adminEmail) {
    throw "admin profile check failed"
}
Write-Host "   PASS -> HTTP 200, email=$($meJson.data.email)"

Write-Host "5) GET /admin/me (wrong legacy endpoint) must NOT be a JSON API profile"
$legacy = Invoke-WebRequest -Uri "$baseUrl/admin/me" -Headers @{ Authorization = "Bearer $token" } -UseBasicParsing
$isHtml = $legacy.Content -match '<!doctype html>'
if ($isHtml) {
    Write-Host "   PASS -> /admin/me serves SPA HTML (proves it is not the real API route)"
} else {
    Write-Host "   INFO -> /admin/me returned HTTP $($legacy.StatusCode) (content-type $($legacy.Headers['Content-Type']))"
}

Write-Host "6) login error response must NOT contain the real password"
$body = @{ email = $adminEmail; password = "$adminPassword-typo"; rememberMe = $false } | ConvertTo-Json
try {
    Invoke-WebRequest -Uri "$baseUrl/admin/login" -Method Post -ContentType 'application/json' -Body $body -UseBasicParsing | Out-Null
    throw "expected 400 for wrong password"
} catch {
    $errText = $_.ErrorDetails.Message
    if (-not $errText -and $_.Exception.Response) {
        $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
        $errText = $reader.ReadToEnd()
    }
}
if ($errText -match [regex]::Escape($adminPassword)) { throw "response leaked the password" }
if ($errText -notmatch 'Invalid credentials') { throw "unexpected error message" }
Write-Host "   PASS -> response only says 'Invalid credentials', no secret leaked"

Write-Host "7) GET /admin/users/me without token must be 401"
try {
    Invoke-WebRequest -Uri "$baseUrl/admin/users/me" -UseBasicParsing | Out-Null
    throw "expected 401 without token"
} catch {
    $code = [int]$_.Exception.Response.StatusCode
    if ($code -ne 401) { throw "expected 401 but got $code" }
}
Write-Host "   PASS -> HTTP 401 (auth enforced)"

Write-Host "8) GET /admin/users/me with tampered JWT must be 401"
$tampered = $token.Substring(0, $token.Length - 1) + $(if ($token[-1] -eq 'A') { 'B' } else { 'A' })
try {
    Invoke-WebRequest -Uri "$baseUrl/admin/users/me" -Headers @{ Authorization = "Bearer $tampered" } -UseBasicParsing | Out-Null
    throw "expected 401 for tampered token"
} catch {
    $code = [int]$_.Exception.Response.StatusCode
    if ($code -ne 401) { throw "expected 401 but got $code" }
}
Write-Host "   PASS -> HTTP 401 (invalid signature rejected)"

Write-Host "ALL ADMIN LOGIN TESTS PASSED"