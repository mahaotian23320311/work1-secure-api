# Live end-to-end check of the API with curl.
#
# Start the server first (from the project root):
#   $env:JWT_SECRET = "demo-secret-0123456789abcdef"; $env:PORT = "5001"
#   .\.venv\Scripts\python.exe wsgi.py
# then:
#   powershell -NoProfile -File .\scripts\live_demo.ps1
#
# The transcript is written to reports/curl-transcript.txt and is the raw
# material for the "testing" section of the report.
#
# JSON bodies are handed to curl through a temporary file ("--data-binary @file")
# because Windows PowerShell 5.1 strips the quotes out of inline -d '{"a":"b"}'.
param(
    [string]$BaseUrl = "http://127.0.0.1:5001",
    [string]$TranscriptPath = "$PSScriptRoot\..\reports\curl-transcript.txt"
)

$ErrorActionPreference = 'Stop'
$script:out = New-Object System.Collections.Generic.List[string]

function Section {
    param([string]$Title, [string]$Command)
    $script:out.Add('')
    $script:out.Add('=' * 78)
    $script:out.Add($Title)
    $script:out.Add('=' * 78)
    $script:out.Add('$ ' + $Command)
    Write-Host $Title
}

function Run {
    param([string[]]$CurlArgs)
    $result = (& curl.exe @CurlArgs 2>&1 | Out-String).TrimEnd()
    $script:out.Add($result)
    return $result
}

function PostJson {
    param([string]$Url, [string]$Json, [string]$Token, [switch]$ShowCode)
    $tmp = [IO.Path]::GetTempFileName()
    [IO.File]::WriteAllText($tmp, $Json, (New-Object System.Text.UTF8Encoding($false)))
    try {
        $curlArgs = @('-s', '-X', 'POST', $Url, '-H', 'Content-Type: application/json', '--data-binary', ("@" + $tmp))
        if ($ShowCode) { $curlArgs += @('-w', "`nHTTP %{http_code}") }
        if ($Token) { $curlArgs += @('-H', "Authorization: Bearer $Token") }
        return (Run $curlArgs)
    }
    finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
}

New-Item -ItemType Directory -Force -Path (Split-Path $TranscriptPath) | Out-Null

Section '1. GET /api/data without a token -> must be 401' "curl -s -i $BaseUrl/api/data"
Run @('-s', '-i', "$BaseUrl/api/data") | Out-Null

Section '2. POST /auth/login with valid credentials -> JWT' "curl -s -X POST $BaseUrl/auth/login -H Content-Type:application/json --data-binary @login.json"
$loginRaw = PostJson -Url "$BaseUrl/auth/login" -Json '{"username":"alice","password":"Alice-Passw0rd!"}'
$token = ($loginRaw | ConvertFrom-Json).access_token
$script:out.Add('token (first 40 chars): ' + $token.Substring(0, 40) + '...')

Section '3. POST /auth/login with a wrong password -> must be 401' "curl -s -X POST $BaseUrl/auth/login --data-binary @wrong.json"
PostJson -Url "$BaseUrl/auth/login" -Json '{"username":"alice","password":"wrong"}' -ShowCode | Out-Null

Section '4. GET /api/data with the token -> 200 + data' "curl -s -H Authorization:Bearer_<token> $BaseUrl/api/data"
Run @('-s', '-H', "Authorization: Bearer $token", "$BaseUrl/api/data") | Out-Null

Section '5. GET /api/me with the token' "curl -s -H Authorization:Bearer_<token> $BaseUrl/api/me"
Run @('-s', '-H', "Authorization: Bearer $token", "$BaseUrl/api/me") | Out-Null

Section '6. SQL injection attempt in ?search= -> 200, zero rows, no error' "curl -s -H Authorization:Bearer_<token> $BaseUrl/api/data?search=OR-1-1"
Run @('-s', '-H', "Authorization: Bearer $token", "$BaseUrl/api/data?search=%27%20OR%201%3D1--") | Out-Null

Section '7. Store an XSS payload and read it back -> escaped' "curl -s -X POST $BaseUrl/api/notes --data-binary @note.json"
$note = PostJson -Url "$BaseUrl/api/notes" -Json '{"title":"<script>alert(1)</script>","body":"<img src=x onerror=alert(2)>"}' -Token $token
$noteId = ($note | ConvertFrom-Json).id
Run @('-s', '-H', "Authorization: Bearer $token", "$BaseUrl/api/notes/$noteId") | Out-Null

Section '8. Request with a garbage token -> 401' "curl -s -H Authorization:Bearer_not.a.jwt $BaseUrl/api/data"
Run @('-s', '-w', "`nHTTP %{http_code}", '-H', 'Authorization: Bearer not.a.jwt', "$BaseUrl/api/data") | Out-Null

Section '9. Security headers on a response' "curl -s -I $BaseUrl/health"
Run @('-s', '-I', "$BaseUrl/health") | Out-Null

$script:out -join "`r`n" | Set-Content -Path $TranscriptPath -Encoding utf8
Write-Host ''
Write-Host "Transcript written to $TranscriptPath"
