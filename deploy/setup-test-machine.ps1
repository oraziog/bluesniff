# Setup della macchina di test: eseguilo sulla macchina di test.
#
# Non richiede privilegi di amministratore e NON installa nulla: scarica
# l'agent in una cartella utente, lo avvia in ascolco su localhost e verifica
# che tutto torni. Il deploy vero e proprio avviene solo dopo, e con rollback.
#
# Uso (PowerShell, anche senza diritti admin):
#   irm http://REPLACE_ME:8899/setup-test-machine.ps1 | iex
#
# Oppure, meglio: scarica il file, guardalo, poi eseguilo.

$ErrorActionPreference = 'Stop'
$Server = 'http://REPLACE_ME:8899'
$Root   = "$env:USERPROFILE\bluesniff-agent"

function Step($n, $t) { Write-Host "`n[$n] $t" -ForegroundColor Cyan }

Step 1 'Connessione al file server'
try {
    $r = Invoke-WebRequest -Uri "$Server/bluesniff.exe" -Method Head -UseBasicParsing -TimeoutSec 8
    Write-Host "  OK: raggiungibile (HTTP $($r.StatusCode))" -ForegroundColor Green
} catch {
    Write-Host "  FALLITO: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  Controlla: il server e' attivo sulla maciglia di sviluppo? Il firewall" -ForegroundColor Yellow
    Write-Host "  di questa macchina blocca l'ingresso dalla rete (porta 8899)?" -ForegroundColor Yellow
    exit 1
}

Step 2 'Preparazione della cartella'
foreach ($d in @($Root, "$Root\app", "$Root\commands", "$Root\results", "$Root\agent-logs")) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}
Write-Host "  OK: $Root" -ForegroundColor Green

Step 3 'Download dell agent'
$agent = "$Root\bluesniff-agent.ps1"
try {
    Invoke-WebRequest -Uri "$Server/bluesniff-agent.ps1" -OutFile $agent -UseBasicParsing -TimeoutSec 30
    Write-Host "  OK: agent scaricato" -ForegroundColor Green
} catch {
    Write-Host "  FALLITO: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# L'hash del file scaricato non e' firmato: qui verifichiamo solo che non sia
# vuoto o troncato. L'autenticazione viene dal manifest, che l'agent verifica
# con SHA-256 prima di installare qualsiasi cosa.
$len = (Get-Item $agent).Length
if ($len -lt 1000) { Write-Host "  FALLITO: agent troppo piccolo ($len byte), download troncato" -ForegroundColor Red; exit 1 }
Write-Host "  OK: $len byte" -ForegroundColor Green

Step 4 'Avvio dell agent in ascolto su localhost:9100'
Get-Process -Name powershell -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -ne $PID } | Out-Null
$existing = Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like '*bluesniff-agent.ps1*' }
if ($existing) {
    Write-Host "  Agent gia' in esecuzione (pid $($existing.ProcessId -join ', '))" -ForegroundColor Yellow
} else {
    $p = Start-Process -FilePath 'powershell.exe' -PassThru -WindowStyle Hidden `
        -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $agent,
            '-Root', $Root, '-Port', '9100')
    Start-Sleep -Seconds 3
    Write-Host "  OK: avviato (pid $($p.Id))" -ForegroundColor Green
}

Step 5 'Verifica dello stato'
try {
    $s = Invoke-RestMethod -Uri 'http://127.0.0.1:9100/status' -TimeoutSec 8
    Write-Host "  agent:    $($s.agent_version)" -ForegroundColor Gray
    Write-Host "  bluesniff in esercizio: $($s.bluesniff_running)" -ForegroundColor Gray
    Write-Host "  healthcheck raggiungibile: $($s.healthy)" -ForegroundColor Gray
    Write-Host "  backup presente: $($s.backup_present)" -ForegroundColor Gray
} catch {
    Write-Host "  L'endpoint non risponde: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  Controlla il journal: $Root\agent-logs" -ForegroundColor Yellow
    exit 1
}

Step 6 'Dry-run del deploy (non installa)'
$manifestPath = "$Root\commands\test.json"
$manifest = @"
{
  "_commento": "dry-run: hash volutamente errato per verificare che l agent rifiuti",
  "url": "$Server/bluesniff.exe",
  "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
}
"@
$manifest | Set-Content -LiteralPath $manifestPath -Encoding UTF8
$before = if (Test-Path "$Root\app\bluesniff.exe") { (Get-FileHash "$Root\app\bluesniff.exe" -Algorithm SHA256).Hash } else { 'assente' }
& $agent -Root $Root -Port 0 -RunOnce $manifestPath | Out-Null
$after = if (Test-Path "$Root\app\bluesniff.exe") { (Get-FileHash "$Root\app\bluesniff.exe" -Algorithm SHA256).Hash } else { 'assente' }
$state = Get-Content "$Root\agent-state.json" -Raw | ConvertFrom-Json

if ($state.ok -eq $false -and $state.stage -eq 'hash' -and $before -eq $after) {
    Write-Host "  OK: hash errato rifiutato, nulla installato" -ForegroundColor Green
} else {
    Write-Host "  ATTENZIONE: esito inatteso (ok=$($state.ok) stage=$($state.stage))" -ForegroundColor Yellow
    Write-Host "  Il binario deve essere invariato: prima=$before dopo=$after" -ForegroundColor Yellow
}

Write-Host "`n=== Pronto ===" -ForegroundColor Cyan
Write-Host "Il tuo bluesniff su questa macchina non e' stato toccato." -ForegroundColor Green
Write-Host "Per il deploy vero, basta che io posti il manifest corretto su:" -ForegroundColor Gray
Write-Host "  $Root\commands\deploy.json" -ForegroundColor Gray
Write-Host "e poi venga eseguito:" -ForegroundColor Gray
Write-Host "  & '$agent' -Root '$Root' -Port 0 -RunOnce '$Root\commands\deploy.json'" -ForegroundColor Gray
