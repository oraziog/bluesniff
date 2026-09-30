# Agente di deployment remoto

Deploy di `bluesniff` sulla macchina di test Windows, progettato con una
regola sola: **nessun deploy può lasciare la macchina senza tool
funzionante**.

## Il principio

L'agente non accetta mai un eseguibile. Accetta un **manifest** con due campi:
un URL e un hash SHA-256. Scarica, verifica l'hash, e solo se coincide
sostituisce il binario. Un file alla cieca, un hash sbagliato o un download
troncato non possono installare nulla.

Se la nuova build non risponde entro 10 secondi, l'agente **ripristina da solo**
il binario precedente. Non serve che tu ci sia: è il punto.

## Perché non spinto e automatico

Un auto-aggiornamento spinto (l'app accetta comandi e si aggiorna da sola)
sembra comodo, ma se sbaglio un flag la macchina diventa inutilizzabile e tu
resti senza accesso. Qui invece ogni operazione che tocca il binario passa da
una copia di backup, e il rollback è automatico. Il criterio che ho usato è:
**un deploy che si può sbagliare in modo sicuro**, non uno che non può
sbagliare.

In più l'agente non ha credenziali e non è esposto sulla rete: l'endpoint HTTP
ascolta solo su `127.0.0.1`. Per usarlo da remoto serve un tunnel, e decidi tu
quando aprirlo.

## Struttura

```
deploy/
  bluesniff-agent.ps1   l'agente
  manifest.example.json esempio di manifest
```

All'avvio crea:

```
agent-root/
  app/bluesniff.exe         il binario in esercizio
  app/bluesniff.exe.prev    backup (il punto di ritorno)
  commands/                 manifest da processare (modalità coda)
  results/                  esiti del deploy
  agent-logs/               journal + stdout/stderr di bluesniff
  agent-state.json          ultimo esito
```

## Avvio sulla macchina di test

```powershell
.\deploy\bluesniff-agent.ps1 -Root C:\bluesniff-agent -Port 9100
```

Primo avvio a mano, per vedere cosa fa. Poi, se tutto è a posto, si mette in
avvio automatico con una task pianificata all'avvio di sistema.

## Uso

Verifica di stato:

```powershell
Invoke-RestMethod http://127.0.0.1:9100/status
```

Deploy (il manifest deve già essere sulla macchina):

```powershell
$manifest = '{"url":"http://host/bluesniff.exe","sha256":"abc...","args":["--listen","--dashboard"]}'
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:9100/deploy -Body $manifest
```

Il risultato dice sempre in quale fase siamo e cosa è successo:

```json
{ "ok": true,  "stage": "done",    "detail": "deploy riuscito, pid 4821" }
{ "ok": false, "stage": "hash",    "detail": "hash non corrispondente: atteso abc..., ottenuto def.... Nessuna installazione." }
{ "ok": false, "stage": "rollback","detail": "nuova build fallita, ripristinata la precedente" }
```

Le fasi sono `start`, `hash`, `health`, `rollback`, `done`, `error`. La fase
`hash` con `ok: false` è il caso più importante: significa che **non è stato
installato niente**, perché il download non corrispondeva.

## Generare il manifest lato sviluppo

```bash
sha256sum target/release/bluesniff.exe
# ->  3f2a...  target/release/bluesniff.exe
```

Metti l'hash nel manifest. Il file deve servire l'eseguibile via HTTP: dalla
macchina di test deve essere raggiungibile, per esempio con
`python -m http.server` sulla mia macchina o un server sulla stessa rete.

## Limiti, detti chiaramente

- L'agente **non installa Npcap né driver**: serve solo il binario, perché
  `bluesniff` usa le API di Windows e non va a pilotare l'adapter direttamente.
- Il test di salute è `GET /api/presence` sulla porta 9000: se in futuro
  cambi la porta del dashboard, va cambiata anche `$HealthUrl` nell'agente.
- L'endpoint è su loopback: per pilotarlo da fuori serve un tunnel SSH o
  Tailscale. Non esporlo direttamente.
- Se l'agente viene ucciso mentre un deploy è a metà, il backup `prev` c'è
  comunque e il riavvio manuale riprende.
