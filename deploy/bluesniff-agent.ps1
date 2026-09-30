<#
.SYNOPSIS
    Agent di deployment di bluesniff per la macchina di test Windows.

.DESCRIPTION
    Progettato con una regola sola: **nessun deploy può lasciare la macchina
    senza tool funzionante**. Ogni operazione che tocca il binario passa da
    una copia di backup, e se la nuova build non risponde entro il timeout il
    rollback è automatico e non richiede intervento umano.

    L'agent NON accetta mai un eseguibile. Accetta solo un *manifest* JSON con
    URL e hash SHA-256: scarica, verifica l'hash, e solo se coincide sostituisce
    il binario. Un binario alla cieca o un hash sbagliato non possono
    installare nulla.

    Non serve un account di servizio ne' credenziali: si parla con l'agent via
    una cartella condivisa o un bind HTTP, e ogni comando viene scritto in un
    journal.

.PARAMETER Root
    Directory di lavoro dell'agent (default: la directory dello script).

.PARAMETER Port
    Porta del piccolo endpoint HTTP di comando (default 9100). 0 = disabilita
    l'endpoint e si usa solo la cartella comandi.

.PARAMETER RunOnce
    Applica un singolo manifest e termina. Serve per il test automatico e per
    un deploy una tantum senza lasciare l'agent in ascolto.

.PARAMETER HealthTimeout
    Secondi da attendere la nuova build prima del rollback. Default 60.

.EXAMPLE
    .\bluesniff-agent.ps1 -Port 9100
#>
[CmdletBinding()]
param(
    [string]$Root = $PSScriptRoot,
    [int]$Port = 9100,
    [string]$RunOnce,
    [int]$HealthTimeout = 60
)

$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path -LiteralPath $Root).Path
$AppDir = Join-Path $Root 'app'
$BinPath = Join-Path $AppDir 'bluesniff.exe'
$PrevPath = Join-Path $AppDir 'bluesniff.exe.prev'
$CmdDir = Join-Path $Root 'commands'
$DoneDir = Join-Path $Root 'results'
$LogDir = Join-Path $Root 'agent-logs'
$StateFile = Join-Path $Root 'agent-state.json'
$HealthUrl = 'http://127.0.0.1:9000/api/presence'

# Quanto aspettiamo la nuova build prima di tornare indietro.
#
# 60 secondi, non 10. Il valore precedente era tarato a occhio e si e' rivelato
# troppo stretto: su una macchina dove bluesniff non era gia' in esercizio,
# l'avvio puo' richiedere diversi secondi prima che la dashboard risponda, e un
# timeout corto fa il peggio possibile: sostituisce un binario funzionante e
# subito dopo lo riporta indietro, lasciando la macchina inutilmente ferma e
# senza sapere se la build fosse davvero buona. Un rollback di troppo e' molto
# piu' costoso di un rollback che arriva tardi.
$HealthTimeoutSec = $HealthTimeout

foreach ($d in @($AppDir, $CmdDir, $DoneDir, $LogDir)) {
    if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}

function Write-Journal($level, $message) {
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $level, $message
    Add-Content -LiteralPath (Join-Path $LogDir ("{0}.log" -f (Get-Date -Format 'yyyyMM'))) -Value $line -Encoding UTF8
    # Write-Host, non Write-Output: quest'ultimo finirebbe nella pipeline e
    # quindi dentro il valore restituito da Invoke-Deploy, sporcando il JSON
    # che l'endpoint HTTP rimanderebbe al client. Il journal resta nel file e
    # a schermo, ma non mescola output e dati strutturati.
    Write-Host $line
}

function Get-FileSha256([string]$path) {
    return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Test-Healthy {
    <# Controlla che bluesniff stia davvero rispondendo. Non basta che il
       processo esista: se parte e poi muore subito, il rollback deve scattare. #>
    try {
        $r = Invoke-WebRequest -Uri $HealthUrl -UseBasicParsing -TimeoutSec 3
        return ($r.StatusCode -eq 200)
    } catch {
        return $false
    }
}

function Get-BlueSniffProcess {
    return @(Get-Process -Name 'bluesniff' -ErrorAction SilentlyContinue)
}

function Stop-BlueSniff {
    $procs = Get-BlueSniffProcess
    foreach ($p in $procs) {
        Write-Journal 'WARN' ("fermo bluesniff pid {0}" -f $p.Id)
        try { Stop-Process -Id $p.Id -Force -ErrorAction Stop } catch { Write-Journal 'ERROR' $_.Exception.Message }
    }
    Start-Sleep -Seconds 2
}

function Start-BlueSniff([string[]]$extraArgs) {
    # I flag di default si aggiungono solo se il manifest non li ripete:
    # altrimenti finirebbero duplicati e il comando si rifiuta.
    $args = @('--listen', '--dashboard')
    foreach ($a in $extraArgs) { if ($args -notcontains $a) { $args += $a } }
    Write-Journal 'INFO' ("avvio: bluesniff {0}" -f ($args -join ' '))
    # NON propaghiamo l'eccezione: un binario non eseguibile (PE invalido,
    # architettura sbagliata) fa fallire Start-Process con un errore, e se
    # l'eccezione salta fuori dal try finiamo in un ramo che NON fa il
    # rollback, lasciando sulla macchina un binario rotto. E' esattamente il
    # guasto che questo agent deve impedire, quindi qui si intercetta e si
    # lascia decidere il flusso di salute.
    try {
        return Start-Process -FilePath $BinPath -ArgumentList $args -WorkingDirectory $AppDir `
            -RedirectStandardOutput (Join-Path $LogDir 'bluesniff.out.log') `
            -RedirectStandardError (Join-Path $LogDir 'bluesniff.err.log') `
            -WindowStyle Hidden -PassThru -ErrorAction Stop
    } catch {
        Write-Journal 'WARN' ("avvio fallito: {0}" -f $_.Exception.Message)
        return $null
    }
}

function Wait-Healthy([int]$timeoutSec) {
    for ($i = 0; $i -lt ($timeoutSec * 2); $i++) {
        Start-Sleep -Milliseconds 500
        if (Test-Healthy) { return $true }
    }
    return $false
}

function Restore-Previous {
    <# Rollback automatico. Se non c'è un backup, non facciamo nulla di
       distruttivo: è peggio lasciare il file rotto che eliminarlo. #>
    if (-not (Test-Path -LiteralPath $PrevPath)) {
        Write-Journal 'ERROR' 'rollback impossibile: nessun backup presente'
        return $false
    }
    Write-Journal 'WARN' 'rollback: ripristino il binario precedente'
    Stop-BlueSniff
    Copy-Item -LiteralPath $PrevPath -Destination $BinPath -Force
    $p = Start-BlueSniff @()
    if ($null -ne $p -and (Wait-Healthy $HealthTimeoutSec)) {
        Write-Journal 'INFO' 'ripristinato: la versione precedente funziona'
        return $true
    }
    Write-Journal 'ERROR' 'rollback completato ma anche la versione precedente non risponde'
    return $false
}

function Invoke-Deploy($manifestPath) {
    <# Applica un manifest: { url, sha256, args: [] } #>
    $result = [ordered]@{ ok = $false; stage = 'start'; detail = ''; manifest = $manifestPath }

    try {
        $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $url = $manifest.url
        $expected = ([string]$manifest.sha256).ToLowerInvariant()
        $extra = @()
        if ($manifest.PSObject.Properties.Name -contains 'args') { $extra = @($manifest.args) }

        if (-not $url) { $result.detail = 'manifest senza url'; return (Complete-Deploy $result) }
        if ($expected -notmatch '^[0-9a-f]{64}$') {
            $result.detail = 'sha256 mancante o malformato: rifiuto di installare'
            return (Complete-Deploy $result)
        }

        $tmp = Join-Path $LogDir ('download-{0}.tmp' -f [guid]::NewGuid().ToString('N'))
        Write-Journal 'INFO' ("scarico {0}" -f $url)
        # file:// e ammesso perche' il file puo' gia' essere sulla macchina
        # (utile per i test e per un deploy senza server HTTP).
        if ($url -like 'file://*') {
            # Sostituzioni letterali (.Replace) e non -replace: con una singola
            # barra la regex non e' valida e l'agente si ferma prima di fare
            # qualsiasi verifica sull'hash.
            $src = $url.Substring('file:///'.Length)
            $src = $src.Replace('/', '\')
            if (-not (Test-Path -LiteralPath $src)) { throw "percorso locale non trovato: $src" }
            Copy-Item -LiteralPath $src -Destination $tmp -Force
        } else {
            Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing -TimeoutSec 120
        }
        $actual = Get-FileSha256 $tmp

        if ($actual -ne $expected) {
            Remove-Item -LiteralPath $tmp -Force
            $result.stage = 'hash'
            $result.detail = ("hash non corrispondente: atteso {0}, ottenuto {1}. Nessuna installazione." -f $expected, $actual)
            Write-Journal 'ERROR' $result.detail
            return (Complete-Deploy $result)
        }
        Write-Journal 'INFO' ("hash verificato: {0}" -f $actual)

        # Backup del binario corrente: e' il punto di ritorno.
        if (Test-Path -LiteralPath $BinPath) {
            Copy-Item -LiteralPath $BinPath -Destination $PrevPath -Force
        }

    Stop-BlueSniff
    # Copia invece di spostare: se il riavvio/rollback fallisce, il download
    # verificato resta disponibile per il debug senza riscaricarlo.
    Copy-Item -LiteralPath $tmp -Destination $BinPath -Force
    Write-Journal 'INFO' 'binario sostituito, avvio'

        $p = Start-BlueSniff $extra
        $result.stage = 'health'
        # Un avvio fallito e un avvio che non risponde sono lo stesso problema
        # dal punto di vista dell'utente: la build non va bene. In entrambi i
        # casi si torna indietro.
        $started = $null -ne $p
        if ($started -and (Wait-Healthy $HealthTimeoutSec)) {
            $result.ok = $true
            $result.stage = 'done'
            $result.detail = ("deploy riuscito, pid {0}" -f $p.Id)
            Write-Journal 'INFO' $result.detail
            Set-DeployState $result
            return (Complete-Deploy $result)
        }

        $why = if ($started) { "non risponde entro $HealthTimeoutSec s" } else { "non e' avviabile" }
        Write-Journal 'WARN' ("la nuova build {0}: rollback" -f $why)
        $restored = Restore-Previous
        $result.stage = 'rollback'
        $result.detail = if ($restored) { 'nuova build fallita, ripristinata la precedente' } else { 'nuova build fallita, rollback non riuscito' }
        Set-DeployState $result
        return (Complete-Deploy $result)
    } catch {
        $result.stage = 'error'
        $result.detail = $_.Exception.Message
        Write-Journal 'ERROR' $result.detail
        Set-DeployState $result
        return (Complete-Deploy $result)
    } finally {
        if ($tmp -and (Test-Path -LiteralPath $tmp)) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function Set-DeployState($state) {
    $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $StateFile -Encoding UTF8
}

function Complete-Deploy($result) {
    Set-DeployState $result
    $name = [IO.Path]::GetFileNameWithoutExtension($result.manifest) + '.result.json'
    ($result | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath (Join-Path $DoneDir $name) -Encoding UTF8
    return $result
}

function Get-Status {
    $procs = Get-BlueSniffProcess
    $state = if (Test-Path -LiteralPath $StateFile) { Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json } else { $null }
    [ordered]@{
        agent_version = '1.0'
        root = $Root
        bluesniff_running = ($procs.Count -gt 0)
        pids = @($procs | ForEach-Object { $_.Id })
        healthy = (Test-Healthy)
        binary_present = (Test-Path -LiteralPath $BinPath)
        binary_sha256 = if (Test-Path -LiteralPath $BinPath) { Get-FileSha256 $BinPath } else { $null }
        backup_present = (Test-Path -LiteralPath $PrevPath)
        last_deploy = $state
        free_gb = [math]::Round((Get-PSDrive -Name ((Get-Item $Root).PSDrive.Name)).Free / 1GB, 1)
    }
}

# Modalita' una tantum: applica il manifest indicato e esce. Nessun loop,
# nessun ascolto: serve al test automatico e al deploy manuale.
if ($RunOnce) {
    if (-not (Test-Path -LiteralPath $RunOnce)) {
        Write-Journal 'ERROR' ("manifest non trovato: {0}" -f $RunOnce)
        exit 2
    }
    $result = Invoke-Deploy $RunOnce
    exit ($(if ($result.ok) { 0 } else { 1 }))
}

# --------------------------------------------------------------------------
# Endpoint HTTP minimo. Risponde a GET /status e POST /deploy (corpo = path
# del manifest, gia' presente sulla macchina). Nessuna scrittura arbitraria:
# il percorso del manifest e' l'unico input, e il contenuto viene validato.
# --------------------------------------------------------------------------
if ($Port -gt 0) {
    # TcpListener puro invece di HttpListener.
    #
    # HttpListener su Windows pretende una ACL di URL (urlacl): senza diritti
    # di amministratore l'agente si avvia e l'endpoint non risponde mai. Il
    # sintomo e' esattamente quello visto sulla macchina di test. Con
    # TcpListener non chiediamo niente al sistema e l'agente resta utilizzabile
    # da un utente normale, che e' il caso per cui esiste.
    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $Port)
    $listener.Start()
    Write-Journal 'INFO' ("endpoint su http://127.0.0.1:{0}/ (TcpListener, senza ACL)" -f $Port)

    while ($true) {
        $client = $null
        try {
            $client = $listener.AcceptTcpClient()
            $stream = $client.GetStream()
            $reader = New-Object IO.StreamReader($stream, [Text.Encoding]::ASCII)

            # Due righe di richiesta bastano: la prima e la richiesta, la
            # seconda gli header. Il corpo viene letto subito dopo.
            $requestLine = $reader.ReadLine()
            if (-not $requestLine) { $client.Close(); continue }
            $parts = $requestLine.Split(' ')
            $method = if ($parts.Length -ge 1) { $parts[0] } else { '' }
            $target = if ($parts.Length -ge 2) { $parts[1] } else { '/' }

            $contentLength = 0
            while ($true) {
                $h = $reader.ReadLine()
                if ($null -eq $h -or $h -eq '') { break }
                if ($h -match '^Content-Length:\s*(\d+)') { $contentLength = [int]$Matches[1] }
            }
            $reqBody = ''
            if ($contentLength -gt 0) {
                $buf = New-Object char[] $contentLength
                [void]$reader.ReadBlock($buf, 0, $contentLength)
                $reqBody = -join $buf
            }

            $path = $target.Split('?')[0].TrimEnd('/')
            $code = 200; $body = ''

            if ($path -eq '/status' -and $method -eq 'GET') {
                $body = (Get-Status | ConvertTo-Json -Depth 5)
            } elseif ($path -eq '/deploy' -and $method -eq 'POST') {
                $manifestPath = $reqBody.Trim()
                if (-not (Test-Path -LiteralPath $manifestPath)) {
                    $code = 400; $body = '{"ok":false,"detail":"manifest non trovato"}'
                } else {
                    $r = Invoke-Deploy $manifestPath
                    if ($r.ok) { $body = ($r | ConvertTo-Json -Depth 5) } else { $code = 500; $body = ($r | ConvertTo-Json -Depth 5) }
                }
            } else {
                $code = 404; $body = '{"error":"non trovato"}'
            }

            $bytes = [Text.Encoding]::UTF8.GetBytes($body)
            $head = "HTTP/1.1 $code " + $(if ($code -eq 200) { 'OK' } elseif ($code -eq 400) { 'Bad Request' } elseif ($code -eq 404) { 'Not Found' } else { 'Error' }) + "`r`n" +
                    "Content-Type: application/json; charset=utf-8`r`n" +
                    "Content-Length: $($bytes.Length)`r`n" +
                    "Connection: close`r`n`r`n"
            $headBytes = [Text.Encoding]::ASCII.GetBytes($head)
            $stream.Write($headBytes, 0, $headBytes.Length)
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush()
        } catch {
            Write-Journal 'ERROR' $_.Exception.Message
        } finally {
            if ($client) { try { $client.Close() } catch {} }
        }
    }
} else {
    Write-Journal 'INFO' 'modalita coda: deposita un manifest in commands/ e riavvia l agent'
    while ($true) {
        Start-Sleep -Seconds 5
        Get-ChildItem -LiteralPath $CmdDir -Filter '*.json' -ErrorAction SilentlyContinue | ForEach-Object {
            Invoke-Deploy $_.FullName
            Move-Item -LiteralPath $_.FullName -Destination (Join-Path $DoneDir ('consumed-' + $_.Name)) -Force
        }
    }
}
