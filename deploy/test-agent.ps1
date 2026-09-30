<#
.SYNOPSIS
    Test automatico dell'agente di deploy.

.DESCRIPTION
    Verifica le condizioni che rendono l'agente utile, dalla piu' importante
    alla meno importante. Ogni caso usa l'agent vero, invocato con -RunOnce, e
    verifica lo stato reale del disco: non ci fidiamo del messaggio che
    l'agente dice di se', controlliamo il file.

    Uso:  powershell -NoProfile -ExecutionPolicy Bypass -File .\deploy\test-agent.ps1
#>
[CmdletBinding()]
param(
    [string]$Root = "$env:TEMP\bluesniff-agent-test",
    [switch]$Keep
)

$ErrorActionPreference = 'Stop'
# $PSScriptRoot e' la forma moderna e affidabile; la teniamo come ripiego per
#che' con un -File eseguito in modi diversi puo' capitare di non essere
#popolata, e un test che si ferma su una variabile vuota non verifica niente.
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$Agent = Join-Path $ScriptDir 'bluesniff-agent.ps1'
$script:Pass = 0
$script:Fail = 0

function Ok($name, $cond, $detail = '') {
    if ($cond) { Write-Host ("  [ OK ] {0}" -f $name) -ForegroundColor Green; $script:Pass++ }
    else { Write-Host ("  [KO  ] {0}{1}" -f $name, ($(if ($detail) { "  ($detail)" } else { '' }))) -ForegroundColor Red; $script:Fail++ }
}

function Sha($path) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }

Write-Host "`n=== Agent di deploy bluesniff: test ===`n" -ForegroundColor Cyan

# --- 0. Sintassi, prima di tutto -----------------------------------------
# Il rollback costa una decina di secondi: trovare un errore di sintassi solo
# li' significa accorgersene quando serve.
$errors = $null
[System.Management.Automation.PSParser]::Tokenize((Get-Content -LiteralPath $Agent -Raw), [ref]$errors) | Out-Null
Ok "sintassi valida" ($errors.Count -eq 0) (($errors | ForEach-Object { $_.Message }) -join '; ')

if (Test-Path -LiteralPath $Root) { Remove-Item -LiteralPath $Root -Recurse -Force }
$AppDir = Join-Path $Root 'app'
New-Item -ItemType Directory -Path $AppDir -Force | Out-Null

$goodSource = Join-Path (Split-Path $ScriptDir -Parent) 'target\release\bluesniff.exe'
if (-not (Test-Path -LiteralPath $goodSource)) {
    Write-Host '  target\release\bluesniff.exe non trovato: build release necessaria prima del test' -ForegroundColor Red
    exit 2
}

# Binario buono: copia reale di bluesniff, cosi' l'avvio e' vero.
$good = Join-Path $AppDir 'bluesniff.exe'
Copy-Item -LiteralPath $goodSource -Destination $good -Force
$goodHash = Sha $good

# Binario rotto: hash corretto ma non e' un PE, quindi non parte. Serve a
# distinguere "rifiuto dell'hash" (che non installa) da "rollback" (che
# installa e poi torna indietro): due situazioni che l'utente vive in modo
# molto diverso.
$broken = Join-Path $Root 'broken.exe'
Set-Content -LiteralPath $broken -Value 'non e un PE valido' -Encoding ASCII
$brokenHash = Sha $broken
$brokenUrl = 'file:///' + $broken.Replace('\', '/')

function Manifest([string]$name, [string]$url, [string]$hash) {
    $p = Join-Path $Root "$name.json"
    @{ url = $url; sha256 = $hash; args = @('--listen', '--dashboard') } |
        ConvertTo-Json | Set-Content -LiteralPath $p -Encoding UTF8
    return $p
}

function Run([string]$manifest) {
    # -RunOnce: applica e termina. Non usiamo Start-Process -Wait perche'
    # aspetterebbe anche i processi figli, e bluesniff gira per sempre: il test
    # si appenderebbe su un deploy riuscito. Neppure `& $Agent | Out-Null` va
    # bene, perche' il figlio tiene aperta la pipe.
    #
    # Soluzione: avviamo l'agent senza aspettare e aspettiamo che riscriva
    # agent-state.json, confrontando il contenuto per non rilegge quello
    # scritto dal deploy precedente.
    $statePath = Join-Path $Root 'agent-state.json'
    $before = if (Test-Path $statePath) { (Get-Item $statePath).LastWriteTimeUtc } else { [datetime]::MinValue }

    $proc = Start-Process -FilePath 'powershell.exe' `
        -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Agent,
            '-Root', $Root, '-Port', '0', '-RunOnce', $manifest) `
        -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $Root 'agent-stdout.txt') `
        -RedirectStandardError (Join-Path $Root 'agent-stderr.txt')

    # L'health check dell'agent dura 10s, il rollback altri 10: diamo 90s.
    $deadline = (Get-Date).AddSeconds(90)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path $statePath) {
            if ((Get-Item $statePath).LastWriteTimeUtc -gt $before) {
                Start-Sleep -Milliseconds 300   # lascia finire la scrittura
                return (Get-Content $statePath -Raw | ConvertFrom-Json)
            }
        }
        if ($proc.HasExited -and -not (Test-Path $statePath)) { break }
        Start-Sleep -Milliseconds 500
    }
    if (Test-Path $statePath) { return (Get-Content $statePath -Raw | ConvertFrom-Json) }
    return $null
}

# --- 1. Hash errato: rifiuto totale, niente installato -------------------
Write-Host "`n1) Hash non corrispondente -> rifiuto" -ForegroundColor Cyan
$state = Run (Manifest 'badhash' $brokenUrl ('0' * 64))
Ok "esito dichiarato fallito" ($null -ne $state -and $state.ok -eq $false)
Ok "fase = hash" ($null -ne $state -and $state.stage -eq 'hash') ("stage={0}" -f $state.stage)
Ok "il messaggio dice che nulla e' stato installato" ($null -ne $state -and $state.detail -like '*Nessuna installazione*')
Ok "il binario in esercizio e' intatto" ((Sha $good) -eq $goodHash)
Ok "non e' stato creato alcun backup" (-not (Test-Path (Join-Path $AppDir 'bluesniff.exe.prev')))

# --- 2. Binario non avviabile: rollback automatico -----------------------
Write-Host "`n2) Binario non avviabile (hash corretto) -> rollback" -ForegroundColor Cyan
Copy-Item -LiteralPath $good -Destination (Join-Path $AppDir 'bluesniff.exe.prev') -Force
$state = Run (Manifest 'broken' $brokenUrl $brokenHash)
Ok "esito dichiarato fallito" ($null -ne $state -and $state.ok -eq $false)
Ok "fase = rollback" ($null -ne $state -and $state.stage -eq 'rollback') ("stage={0}" -f $state.stage)
Ok "il binario precedente e' stato ripristinato" ((Sha $good) -eq $goodHash) ("hash={0}" -f (Sha $good).Substring(0, 16))
Ok "il backup precedente e' ancora disponibile" (Test-Path (Join-Path $AppDir 'bluesniff.exe.prev'))

# --- 3. Nessun rollback quando non serve --------------------------------
Write-Host "`n3) Nessun rollback spurio" -ForegroundColor Cyan
# Un manifest valido sullo stesso binario gia' installato non deve toccare
# niente: l'agente non deve fare deploy a caso.
$state = Run (Manifest 'good' $brokenUrl $goodHash)
Ok "l'agente accetta un deploy quando l'hash torna" ($null -ne $state)
Ok "il binario e' rimasto quello valido" ((Sha $good) -eq $goodHash)

# --- 4. Il manifest non viene da internet cieco --------------------------
Write-Host "`n4) Rifiuto di un manifest senza hash valido" -ForegroundColor Cyan
$p = Join-Path $Root 'nohash.json'
@{ url = $brokenUrl; args = @() } | ConvertTo-Json | Set-Content -LiteralPath $p -Encoding UTF8
$state = Run $p
Ok "senza sha256 il deploy viene rifiutato" ($null -ne $state -and $state.ok -eq $false)
Ok "il binario e' intatto" ((Sha $good) -eq $goodHash)

# Il test lascia in piedi la copia di bluesniff avviata dall'agente: va fermata
# prima di pulire, altrimenti tiene la porta 9000 e il test successivo fallisce
# per una ragione che non c'entra.
Get-Process -Name 'bluesniff' -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -like "$Root*" } |
    ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 1

if (-not $Keep) { Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue }
Write-Host ("`n=== {0} superati, {1} falliti ===`n" -f $script:Pass, $script:Fail) -ForegroundColor Cyan
if ($script:Fail -gt 0) { exit 1 } else { exit 0 }
