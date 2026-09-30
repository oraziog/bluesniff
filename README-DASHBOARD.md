# Bluesniff — Dashboard e strumenti di diagnostica

Questa guida copre i comandi e le funzionalità aggiunte al progetto:
la dashboard web in stile bluehood, il comando di diagnostica radio `--inq`
(monitor continuo + output JSON) e le notifiche ntfy.

Binario: `target/release/bluesniff.exe` (compila con `cargo build --release`).

---

## 1. Dashboard web (`--dashboard`)

Interfaccia in stile bluehood: topbar con stato, sidebar con statistiche e
filtri, tabella dispositivi ordinabile con ricerca, modale di dettaglio con
heatmap e storico RSSI, radar di prossimità e pannello Radio.

### Avvio

```bash
# Scansione BLE + dashboard insieme (consigliato)
bluesniff.exe --listen --dashboard

# Solo dashboard (per heatmap/eventi, senza scansionare)
bluesniff.exe --dashboard

# Visibile dall'intranet (tutte le interfacce)
bluesniff.exe --listen --dashboard --dashboard-addr lan
```

All'avvio il browser di default si apre **da solo** su `http://localhost:9000`
(puoi comunque aprire a mano):

| Dove | URL |
|---|---|
| Sul PC stesso | `http://localhost:9000` |
| Da un altro dispositivo della rete | `http://<IP-del-PC>:9000` (l'IP viene stampato all'avvio con `--dashboard-addr lan`) |

### Condividi su intranet

Sotto la topbar c'è la barra **🔗 Collegato a:** con gli URL condivisibili
(es. `http://192.168.1.10:9000`, tag `intranet`/`tailnet`/`VPN`) e il
pulsante **"Condividi su intranet"**: apre una modale con l'indirizzo da
condividere e il tasto **📋 Copia** — perfetto per inviare il link a chi è
sulla stessa rete. Chi si collega da remoto (via VPN/tailnet) non può creare
un link LAN locale, quindi la modale mostra il link del server BT che sta già
usando. Il link del dispositivo singolo si ottiene dalla sua scheda
(button **"Condividi link"**, formato `?mac=...`).

> **Firewall**: per accedere dalla rete, apri la porta una volta sola da
> PowerShell come amministratore:
> ```powershell
> netsh advfirewall firewall add rule name="Bluesniff Dashboard 9000" dir=in action=allow protocol=TCP localport=9000
> ```
> Con `--dashboard-addr lan` la dashboard è visibile a tutta la rete: usala
> solo su reti fidate. Senza il flag resta su `localhost`.

### Pannelli della sidebar

| Pannello | Contenuto |
|---|---|
| **Statistiche** | Identificati, attivi ora, nuovi in 1h, randomizzati — **cliccabili**: un click applica il filtro corrispondente (indicato sopra la tabella: `Dispositivi : N (Filtro ...)`) |
| **Log RAW** | Pagina **📜 LOG RAW** (pulsante nel pannello Radio): live view degli ultimi annunci BLE per pacchetto con timestamp al ms, hex AD completo e decodifica (Flags, nomi, iBeacon, **Apple Continuity**, **Fast Pair con nome del modello**, **Samsung SmartTag**, **Eddystone URL/TLM**, **Google Find My anti-stalking**). Pannello **Per dispositivo** con pacchetti, RSSI min/medio/max, payload distinti e **cadenza** (mediana/P95: la firma del protocollo); click per filtrare, con filtro salvato nel link. Filtri MAC/nome/hex, interruttore registrazione on/off e **export per intervallo data-ora → data-ora/adesso** in **CSV**, **JSONL** o **PCAPNG** (si apre in Wireshark, linktype BLE LL). Guida completa in [RAWLOG.md](RAWLOG.md). Il log (`raw_log.jsonl`) è attivo di default durante la scansione, ruota a 64 MB con retention di 7 giorni |
| **Radio** | Stato adattatore (ON/OFF, nome, MAC), **🎯 Radio attiva** (quella scelta con `--radio`, altrimenti "predefinita di sistema"), **conteggio pacchetti BLE** + grafico a barre per finestra (60×5s), avviso rosso "radio muta" dopo 2 min di silenzio (banner + allarme acustico, silenziabile), pulsanti **⟳ Riprova scansione** e **⟳ Reset radio (off/on)** — quest'ultimo spegne e riaccende la radio per sbloccare uno scanner LE muto senza riavviare il PC, con l'esito mostrato sotto il pulsante, e blocco **📏 Portata dongle**: attenuazione ambiente stimata (P10 dei path loss dei dispositivi vicini, cap 25 dB), portata teorica al floor −96 dBm e conteggio campioni — la stessa attenuazione **corregge le distanze** mostrate nel radar/scheda |
| **RADAR** | Dispositivi come punti: distanza dal centro = RSSI (anelli di zona), angolo stabile per MAC, spazzata animata, **linea del tracciato storico** del movimento (RSSI interpolati, colore per zona: rosso=immediate, ambra=near, blu=far, grigio=remote). L'RSSI è **stabilizzato da un filtro alpha-beta 1-D per dispositivo** (idea da bluetooth-arsenal/BTScan): i tracciati, le zone e le distanze non saltano a ogni campione (un singolo campione anomalo viene smorzato di ~2/3). Etichetta compatta (un MAC senza nome appare come 4 ottetti, es. `AA:BB:CC:DD:`) ma **il tooltip mostra il MAC intero** a 6 ottetti e, su una **riga dedicata sotto**, la **distanza stimata in metri** 📏 (quando disponibile) con la connettibilità 🔗/📡 — stessa info nella riga del radar ingrandito. **Marcatori minaccia**: 👻**viola** = annuncio popup/phantom, ⚠**rosso** = CVE note (in entrambi i radar, con legenda) |
| **Filtra / Per classe** | Attivi ora, Identificati, Sconosciuti, Randomizzati, Seguiti (★), **⚠ Con rischi** (CVE note, annuncio phantom o servizi SDP sensibili — conteggio live), **🏷 Tracker** (annunci stile tag: Apple Continuity, Swift Pair, Samsung EasySetup, Fast Pair 0xFE2C, Tile 0xFEED — conteggio live) , **📌 Statici** (RSSI a varianza quasi nulla — falso positivo ambientale, conteggio live) e **🔄 Rotanti** (più MAC che condividono lo stesso fingerprint BLE — un solo dispositivo fisico, conteggio live) e classi: Telefoni, Computer, Audio, Orologi, IoT, Veicoli, Altri |
| **Inquiry Classic** | Ultimo risultato dell'inquiry + pulsante **↻ Ripeti inquiry (~7s)** |
| **Ultimi eventi** | Feed del monitor `--inq` (file `inq_events.jsonl`): nuovi `[+]`, pacchetti `📡`, spariti `[-]` e **cambi di segnale RSSI `[~]`** (es. `-96→-88 dBm ▲`) — con filtri per tipo **Tutti/Nuovi/Pacchetti/Spariti/Spam** (un click filtra subito il feed, lo stato attivo è evidenziato; se non c'è nessun evento di quel tipo compare l'avviso col filtro attivo), contatore "ultima ora" e pulsante **▶ Avvia monitor** che lancia il monitor come processo separato (no secondo terminale; diventa "■ Ferma monitor") |

### Falsi positivi ambientali (📌 / 🔄)

La dashboard applica in tempo reale il filtro falsi positivi (stessa matematica del report offline
`--static` — modulo fpfilter, idea correlate):

- **📌 statico** — l’RSSI di un dispositivo ha varianza < 4.0 con almeno 5 campioni: segnale
  ambientale quasi immobile (Smart-Tag dietro il muro, PC/TV fisso, antenna). Badge nella riga della
  tabella, dettaglio nella scheda ("📌 Falso positivo ambientale") e marcatore nel tooltip del radar.
- **🔄 rotante** — il fingerprint dell’annuncio (payload cifrato Apple/Samsung/Google) è condiviso
  da più MAC: è lo stesso dispositivo fisico che ruota l’indirizzo. Il badge mostra quanti MAC
  sono stati accorpati (es. `🔄 3 MAC`); scheda e tooltip riportano il dettaglio.

I due filtri **📌 Statici** e **🔄 Rotanti** nel pannello Filtra della sidebar mostrano solo queste
categorie, con conteggio live; i dispositivi marcati restano comunque visibili nella lista completa
(il filtro non nasconde nulla di default: è un’etichetta, non un’eliminazione). Il report offline
`bluesniff --static [presenze.csv]` stampa gli stessi falsi positivi e l’accorpamento in bucket di
un minuto, utile per capire quali segnali fissi ignorare durante l’analisi.

### Interazioni

- **Click su una riga** → modale di dettaglio: nome, classe, MAC, vendor,
  RSSI + zona, **distanza stimata in metri** con Tx Power di riferimento
  (se l'AD 0x0A manca si usa il **measured power del payload iBeacon**
  0x004C, indicato come `· iBeacon`) e **connettibilità** (Sì 🔗 / No 📡
  dai flags AD 0x01), primo/ultimo avvistamento, **heatmap attività oraria
  e giornaliera** (da `presenze.csv`), grafico storico RSSI della sessione.
- **✏️ Rinomina dispositivo** nella scheda: il nome personalizzato viene
  salvato in `names.txt` accanto all'eseguibile, vince su quello
  pubblicizzato e vale anche ai prossimi avvii (vuoto = ripristina).
- **Nel feed eventi i dispositivi sono cliccabili**: `[+]` / `[-]` / `[~]`
  aprono la scheda del dispositivo (anche se non è ancora nella tabella,
  es. dashboard-only con monitor separato).
- **🔌 Sonda GATT e 📞 Sonda SDP** nella scheda dispositivo (semi-attive,
  **solo lettura**: nessuna trasmissione).
  - *GATT*: si connette al BLE e stampa servizi/characteristic con nomi
    amichevoli provenienti dall'intero database ufficiale Bluetooth SIG
    (83 servizi e 504 characteristic, importato da blecat): `Device
    Information`, `Battery Service`, `Heart Rate`, `Battery Level`…
    insieme a proprietà e
    valori letti del Device Information → riga **≈ produttore · modello**
    (es. per una Sony senza nome nel campo Model ID) + badge ⚠ CVE se il
    modello matcha il database. Sui device non abbinati Windows può
    chiedere l'accesso: la scheda lo spiega chiaramente.
  - *SDP*: discovery istantanea dei servizi classici del dispositivo
    (stile bluing `br --sdp`) via WinRT RFCOMM: OBEX, PBAP, MAP, HFP,
    SIM Access… con canale e ServiceName — la verifica definitiva di
    "è un telefono" anche quando il nome è assente. Funziona anche
    senza pairing.
  - Risultati memorizzati: riaprendo la scheda ritrovi l'ultima sonda.
- **Click sul radar** (o "Ingrandisci") → radar grande (finestra modale
  più ampia: max-width `min(96vw, 1100px)` e max-height 96vh — niente
  scrollbar laterale): dispositivo evidenziato con anello pulsante,
  tracciato storico in primo piano e pulsante per la scheda completa.
- **Vista compatta** (`c`): il **MAC compare per primo** nella riga (nome/
  badge dopo), allineato con l'ordine delle colonne della vista normale.
- **Click sulle intestazioni** della tabella → ordina; casella di ricerca →
  filtra per MAC/vendor/nome; paginazione 25/50/100.
- **Scorciatoie**: `/` cerca · `r` aggiorna · `c` vista compatta · `1`–`5`
  filtri rapidi · `n` modale notifiche · `?` elenco scorciatoie · `Esc` chiude.

### Notifiche ntfy (🔔)

Pulsante **"Notifiche ntfy"** nella sidebar (o tasto `n`): configura
**topic**, **server** (default `https://ntfy.sh`), e i toggle
**Abilitato / Arrivo / Partenza** per i dispositivi **seguiti** (★, da
`bt_known.txt`). Il salvataggio persiste in `ntfy.txt` + `ntfy_settings.txt`
accanto all'eseguibile ed è condiviso a runtime con il tracker di `--listen`.

### Dispositivi seguiti (bt_known.txt)

**Nella scheda di ogni dispositivo c'e' il pulsante ⭐ Segui**: scrive la riga
in `bt_known.txt` e vale subito, senza riavviare `--listen`. Il pulsante si
inverte in **✖ Smetti di seguire** per rimuoverla. La stella compare
immediatamente nella tabella, non alla finestra di scansione successiva: se
l'utente deve aspettare, il pulsante sembra rotto.

Quando non hai ancora seguito nessuno, il filtro **★ Seguiti** mostra un
riquadro che spiega come accenderlo. Un contatore a zero senza istruzioni e'
solo un numero che non dice nulla.

Se il dispositivo non ha un nome pubblicizzato, il pulsante avvisa: in
`bt_known.txt` finira' come MAC e le notifiche useranno il MAC come nome.

L'editing del file e' **preservante**: il pulsante aggiunge in fondo e
`unfollow` toglie una riga sola. Commenti, righe vuote, ordine e le persone
gia' assegnate agli altri dispositivi non vengono mai riscritti.

In alternativa si edita il file a mano (o con `bluesniff --edit-known`),
una riga per dispositivo:

```
# BTMAC;Nome;Persona
EC:ED:73:65:AC:45;Moto G73;Mario
```

- Il dispositivo appare con la stella **★ Seguiti** e nel conteggio dedicato;
- `--listen` lo **proba attivamente** (page classic) ogni minuto;
- Le notifiche ntfy di arrivo/partenza scattano su questi dispositivi;
- Il pannello **Inquiry Classic** lo trova anche se non trasmette annunci BLE;
- **Auto-SDP**: appena il telefono **diventa presente**, `--listen` lancia
  da solo la 📞 Sonda SDP (una volta per presenza) e salva la fingerprint
  dei servizi: riga di tipo `sdp` in `presenze.csv` (colonna *hint* =
  servizi, es. `OBEX Object Push | PBAP | MAP`) + cache `sdp:<mac>` nella
  dashboard (la scheda la mostra senza rilanciare la sonda).

---

## 2. Diagnosi radio (`--inq`)

Verifica in un colpo solo se la radio riceve: stato adattatore, conteggio
pacchetti BLE (5s) e inquiry classic (discovery GIAC).

```bash
# One-shot: radio + BLE 5s + inquiry classic ~3s
bluesniff.exe --inq 3

# Monitor continuo: ripete il ciclo ogni ~15s, stampa SOLO i cambiamenti
# ([+] nuovi, [-] spariti, pacchetti). Fermati con q o Ctrl+C.
bluesniff.exe --inq
```

Interpretazione:

| BLE | Classic | Diagnosi |
|---|---|---|
| 0 pacchetti | 0 dispositivi | la radio non riceve fisicamente — controlla il pass-through USB del dongle (Impostazioni → Bluetooth → Aggiungi dispositivo) |
| >0 | 0 | normale: nessun dispositivo in modalità discoverable |
| >0 | >0 | radio sana, dispositivi presenti |

---

## 3. Output JSON per script (`--inq-json`)

```bash
# Una riga JSON per ciclo + riga finale di stop; stdout pulito (solo JSON)
bluesniff.exe --inq --inq-json

# One-shot con JSON: --inq N --inq-json
```

Esempio di riga:

```json
{"event":"cycle","ts":"2026-09-01T18:54:11Z","cycle":1,"packets":0,
 "ble_unique":0,"new_devices":[{"type":"classic","mac":"EC:ED:73:65:AC:45",
 "name":"moto g73 5G","class":"0x5A020C"}],"gone_devices":[],"radio_on":true}
```

- In modalità JSON il feed colorato (nuovi/pacchetti/spariti con orario)
  viene scritto su **stderr**, così stdout resta leggibile da script/pipe;
- Ogni evento è anche **appendato a `inq_events.jsonl`** (max 500 righe)
  accanto all'eseguibile — è ciò che legge il pannello "Ultimi eventi"
  della dashboard. Funziona con processi separati: monitor in un terminale,
  dashboard in un altro.

Esempio con Python:

```bash
bluesniff.exe --inq --inq-json | python -c "
import json, sys
for line in sys.stdin:
    e = json.loads(line)
    for d in e.get('new_devices', []):
        print('NUOVO:', d['mac'], d['name'], d['type'])
"
```

---

## 4. Riepilogo comandi

| Comando | Cosa fa |
|---|---|
| `--listen [sec]` | scansione passiva+attiva → `presenze.csv` |
| `--dashboard` | interfaccia web su `:9000` (con `--listen` mostra dati live) |
| `--dashboard-addr lan` | ascolta su tutte le interfacce (intranet) e stampa gli URL |
| `--inq [sec]` | diagnosi one-shot (radio + BLE + inquiry classic) |
| `--inq` (senza arg) | monitor continuo dei cambiamenti, stop con `q` |
| `--inq-json` | output JSON machine-readable (stdout pulito, feed colorato su stderr) |
| `--track` / `--record` | scoperta via stack btleplug (usata per confronto) |

---

## 5. Note

- Lo stato della dashboard è **cumulativo** per la durata del processo:
  avvistamenti, primo/ultimo contatto e storico RSSI si accumulano.
- L'heatmap nel modale è calcolata da `presenze.csv` (aggregazione per ora
  e giorno della settimana): per dati storici usa `--patterns` sullo stesso
  file.
- **`presenze.csv` include la colonna `stazione`**: il MAC dell'adattatore
  BT del server che ha registrato la riga (es. `8C:88:2B:31:5B:74`).
  Serve a distinguere più stazioni sulla stessa rete nelle analisi future;
  i file pre-esistenti senza la colonna continuano a funzionare
  (il campo è opzionale).
- **Classificazione OROLOGIO corretta**: i telefoni Galaxy senza nome
  (che pubblicizzano solo l'hint SmartThings Find, usato anche dai
  SmartTag) non vengono più classificati come orologi, e il token "fit"
  troppo generico è stato sostituito con "fitbit/fitness/miband/amazfit".
- Tutti i file di configurazione (`bt_known.txt`, `ntfy.txt`,
  `ntfy_settings.txt`, `presenze.csv`, `inq_events.jsonl`) vivono accanto
  all'eseguibile.

---

## 6. Vulnerabilità note (CVE)

Il dispositivo espone il **Google Fast Pair Model ID** estratto dallo
service data `0xFE2C` (3 byte big-endian) quando il device lo annuncia
(la maggior parte di auricolari e speaker Android lo fa). Il Model ID
identifica il **modello esatto** del prodotto, quindi si può verificare se
soffre di vulnerabilità note.

Il database vive in **`fastpair_models.txt`** accanto all'eseguibile
(stesso schema di `names.txt`), una voce per riga:

```text
key;vendor;model;CVE;description
```

- `key` **numerica** = match sul Model ID esatto (es. `13911719` =
  Sony WH-1000XM5);
- `key` **`name:<pattern>`** = match case-insensitive su nome
  pubblicizzato / hint annuncio / vendor (per i device senza Fast Pair,
  es. i chip ESP32);
- `key` **`oui:<AA:BB:CC>`** = match sul prefisso MAC del dispositivo
  (primi 3 ottetti → famiglia chip, es. `oui:24:0A:C4` = Espressif
  ESP32): funziona anche quando il device non pubblicizza né Model ID né
  nome, basta l'OUI nel MAC visto via inquiry classic o BLE;
- righe vuote o che iniziano con `#` = commento.

È precompilato con:

- **CVE-2025-36911 (WhisperPair)** — interi modelli di audio Fast Pair
  (Sony WH-1000XM4/5/6, WF-1000XM5, JBL Tune Beam / Clip 5 / Live 775 NC,
  Pixel Buds Pro 2, Marshall, OnePlus, Redmi, Nothing, Soundcore, Jabra,
  Logitech) vulnerabili all'**hijack dell'accessorio accoppiato** con
  firmware precedente a settembre 2025 (ricerca KU Leuven COSIC, IEEE S&P
  2026 — vedi [WhisperPair](https://github.com/KULeuven-COSIC/WhisperPair));
- **CVE-2025-27840** — chip Espressif ESP32 con 29 comandi HCI nascosti
  (es. `0xFC02` write memory), pattern `name:esp32`.

Dove compaiono gli avvisi:

- **Dashboard**: badge rosso `⚠ CVE-xxxxx` accanto al nome nella tabella
  e sezione "⚠ Vulnerabilità note" nella scheda del dispositivo
  (con CVE, produttore/modello e descrizione); la riga "Model ID Fast
  Pair" nella scheda mostra il valore grezzo;
- **Monitor `--inq`**: quando appare un dispositivo vulnerabile il feed
  stampa `[CVE] <mac> <nome> — CVE-xxxxx (<modello>)` (in JSON:
  campo `cves` negli `new_devices`).

Per aggiungere modelli basta scrivere una riga nel file e riavviare
(il database viene letto una volta all'avvio del processo).

---

## 7. Rilevamento spam BLE (👻)

Portato dal progetto [Bluetooth-LE-Spam](https://github.com/simondankelmann/Bluetooth-LE-Spam)
(solo la *parte detector*, nessuna trasmissione/attacco): bluesniff riconosce
passivamente le famiglie di annunci "popup/phantom" che gli spammer
(Flipper Zero, app di spoofing) usano per generare dialoghi fastidiosi:

| Famiglia | Firma nel payload |
|---|---|
| Apple Continuity "New Device" | manufacturer `0x004C`, primo byte `0x07` (ProximityPair) |
| Microsoft Swift Pair | manufacturer `0x0006`, tipo `0x01` o prefisso `03 00 80` |
| Samsung Easy Setup | manufacturer `0x0075`, payload che inizia con `42 09` |
| Google Fast Pair | service UUID `0xFE2C` (Model ID nei primi 3 byte) |

**Come funziona il rilevamento** (nel monitor `--inq`): la presenza di un
singolo annuncio di queste famiglie è normalissima (qualunque earbud
Android usa Fast Pair), quindi l'allarme scatta solo con soglie conservative:

- **Burst**: ≥ 5 annunci "popup hard" (apple-popup / swift-pair /
  samsung-easysetup) nella stessa finestra;
- **Spoof Fast Pair**: lo stesso Model ID visto da **≥ 3 MAC distinti**
  (un solo dispositivo reale ha un solo MAC — è la firma della rotazione
  MAC di chi spamma).

Quando scatta, il monitor stampa nel feed colorato
`[SPAM] possibile spammer BLE nelle vicinanze — ...`, scrive il campo
`spam` nella riga JSON di ciclo (`detected`, `popup_hard`, `by_type`,
`dup_model_ids`) e il pannello **Ultimi eventi** della dashboard mostra la
riga `[SPAM]` con il filtro dedicato **👻 Spam**.

I dispositivi che pubblicizzano annunci Apple popup vengono marcati con la
categoria **👻 Phantom** (badge in tabella + sezione nella scheda) e finiscono
nel filtro Phantom della sidebar. È un **marcatore difensivo**, non un
verdetto: un Apple TV o auricolari veri in modalità pairing usano lo stesso
annuncio.

### Nome prodotto dal Model ID

Il file **`model_names.txt`** (accanto all'eseguibile, generato dal dataset
di Bluetooth-LE-Spam / Xtreme-Firmware: 467 modelli) risolve il Model ID
Fast Pair nel nome reale del prodotto: così un dispositivo che non
pubblicizza il proprio nome appare comunque come "Sony XM5", "JBL Flip 6"
ecc. in tabella e scheda. Formato: `model_id_decimale;nome` per riga, file
editabile e arricchibile a mano.

---

### Come si riconoscono i tracker (senza nome pubblicizzato)

Le firme sono verificate da **AirGuard** (TU Darmstadt/SEEMOO) e dalla
**spec Google FHN v1.3**:

| Segnale BLE | Tracker | Dove appare |
|---|---|---|
| Apple 0x004C tipo 0x07 (Continuity "New Device") | iPhone/AirPods popup (e spoof) | badge 👻 *Apple Continuity popup* |
| Apple 0x004C tipo 0x12 (payload Find My) | **AirTag**, Chipolo ONE Spot, Pebblebee Find My | badge 👻 *Apple Find My (AirTag)* |
| Service UUID 0xFEED | **Tile** | badge 👻 *Tile tracker* |
| Service 0xFD5A (service data 0x10-prefisso) | **Samsung SmartTag / SmartTag+ / SmartTag 2 / Solum** | badge 👻 *Samsung SmartTag* |
| Service 0xFD69 | **Samsung Find My Mobile** (beacon SmartThings Find) | badge 👻 *Samsung Find My* |
| Service 0xFE33 | **Chipolo** (app Chipolo) | badge 👻 *Chipolo tracker* |
| Service 0xFA25 | **Pebblebee** (app Pebblebee) | badge 👻 *Pebblebee tracker* |
| Service data 0xFEAA frame 0x40/0x41 | **Google Find My Device**: Chipolo One Point, Pebblebee, Motorola, Hama, Eufy, Jio, Rolling Square | badge 👻 *Google Find My tag* (0x41 = anti-stalking, MAC fisso 24 h) |
| Samsung 0x0075 EasySetup (42 09) | **SmartTag** (setup app) | badge 👻 *Samsung EasySetup* |
| Fast Pair 0xFE2C + Model ID | auricolari Android, SmartTag 2 | nome prodotto da `model_names.txt` |

La famiglia compare in tre punti: **badge nella riga della tabella**
(titolo "Tracker BLE riconosciuto" per i tracker, "possibile spoof BLE"
per i popup), **tooltip del radar** (es. "👻 Chipolo tracker" invece del
generico "phantom") e **scheda dispositivo** (etichetta 🏷 *Tracker BLE*).

Nota: **AirTag, Tile e SmartTag non hanno Model ID Fast Pair pubblici**, quindi
`model_names.txt` non può contenerli: vengono riconosciuti dai segnali sopra.
Il filtro **🏷 Tracker** li aggrega tutti (inclusi i dispositivi Fast Pair
come gli auricolari: è per definizione un filtro "annunci stile tag", non un
verdetto sul tipo di prodotto). Il frame 0xFEAA viene accettato solo col
primo byte 0x40/0x41: Eddystone (stesso UUID, primo byte 0x00/0x10/0x20/0x30)
non viene confuso con un tracker.

## 8. Sonda automatica e report di sicurezza

### Auto-SDP sui telefoni seguiti

Quando un telefono di `bt_known.txt` **diventa presente** nel probe attivo
di `--listen`, la 📞 Sonda SDP parte automaticamente (una sola volta per
presenza, senza toccare la UI). In più, se il telefono **compare prima
nell'inquiry classic** (page-scan/discoverable), la sonda parte subito da
lì invece di aspettare il ciclo di 60 s (`auto-SDP via inquiry` nel log).
In entrambi i casi:

- scrive una riga **`sdp`** in `presenze.csv` con la fingerprint servizi
  nella colonna *hint* (es. `OBEX Object Push | PBAP | MAP`) e la stazione
  in coda — utile per le analisi successive (identificare "è un telefono"
  anche a posteriori);
- memorizza il risultato nella cache dashboard (`sdp:<mac>`): riaprendo la
  scheda del dispositivo i servizi sono già lì;
- logga in console `auto-SDP <mac> -> N servizi (esposizioni: …)`.

### Risk chips nella Sonda SDP

La sonda SDP valuta i servizi trovati con le mappature della ricerca di
sicurezza Bluetooth (**BlueToolkit, WOOT'25**) e mostra badge ⚠ ambrati:

| Servizio | Nota esposizione |
|---|---|
| MAP (0x1131/0x1132, SMS/MMS) | possibile **hijack account** / lettura SMS se accettato senza auth (BlueToolkit WOOT'25) |
| OBEX Object Push (0x1105) | famiglia **BlueSnarf**: su stack OBEX datati accesso ai file senza autenticazione |
| PBAP (0x112F/0x1130) | possibile **esfiltrazione rubrica** se la connessione non richiede auth |
| OBEX File Transfer (0x1106) | trasferimento bidirezionale: verificare che richieda autenticazione |
| SIM Access (0x112D/0x112E) | se non protetto, chi si connette può operare sulla SIM |

Non sono verdetti: un telefono normale espone MAP/PBAP; il rischio nasce se
li accetta **senza autenticazione**.

### 🛡 Report sicurezza (export JSON)

Pulsante **"🛡 Report sicurezza"** in toolbar (o `GET
/api/export/security`) accanto a "Export CSV": genera un JSON in stile
BlueToolkit con, per ogni dispositivo che ha riscontri — **CVE note**
(match su Model ID / nome / **OUI**), **servizi SDP** rilevati, **risk
chips** e le **note di esposizione** aggregate — oltre a conteggi totali
(`device_count`, `findings_count`). I dispositivi puliti compaiono solo
nel totale. Il file si chiama `security-report-<data>.json`.
## 9. Banco di prova deterministico (BLE_HackMe)

[BLE_HackMe](https://github.com/smartlockpicking/BLE_HackMe) (licenza MIT)
è un'app Windows 10/11 (UWP) che simula a livello radio periferiche BLE
funzionanti — smart bulb, serratura, beacon, sensori GATT — con lo stesso
stack WinRT del nostro listener (`Windows.Devices.Bluetooth`). È un banco di
prova deterministico: non dipendi dai dispositivi che passano per strada.

### Installazione

- Dal **Microsoft Store**: cerca “BLE_HackMe” (id `9N7PNVS9J1B7`).
- Da sorgente: clona la repo, apri `cs/BLE_Hackme.sln` in Visual Studio
  (Community basta), *Build* e *Deploy* nel computer locale.

### Topologia consigliata

Il nostro scanner usa un dongle pass-through dentro una VM: un PC non vede i
propri annunci. Quindi il banco di prova migliore è un **secondo PC Windows**
che pubblica con BLE_HackMe a 1–5 m dalla stazione, in stanza chiusa per avere
un RSSI stabile. La stazione resta in ascolto normale:
`bluesniff.exe --listen --dashboard` (o `--inq` per il feed eventi).

### Scenario BLE_HackMe → cosa verifichi

| Scenario | Cosa testare in bluesniff |
|---|---|
| **3. Advertisements** | scoperta BLE: nome, vendor/OUI, classe; riga in tabella, radar RSSI con zona e distanza, heatmap presenze; con RSSI stabile per ~1 minuto il device diventa **📌 statico** (filtro falsi positivi) |
| **4. Beacons (iBeacon)** | hint “Apple iBeacon (uuid=…, major=…, minor=…, tx=… dBm)” nella scheda + riferimento di distanza dal Tx. Nota: un iBeacon **non** deve accendere 👻 Spam / 🏷 Tracker — è un buon test negativo del classificatore |
| **5. Manufacturer Advertisements** | hint vendor e conteggi per tipo |
| **7–8. Read / Notifications** | Sonda GATT completa: il simulatore espone servizi GATT reali (Heart Rate `0x180D`, Battery `0x180F`, Current Time `0x1805`, più i custom LightBulb/QuickLock). Con il database SIG i nomi escono leggibili accanto agli UUID: “Heart Rate”, “Battery Service”, “Current Time”, “Battery Level”, “Heart Rate Measurement”… |

Se la sonda riceve *AccessDenied*, abbina prima il device simulato da
*Impostazioni → Bluetooth* e riprova (stessa regola dei telefoni reali). La
sonda resta **solo lettura**.

### Limite onesto: i frame 👻 phantom/tracker

BLE_HackMe non emette le famiglie phantom/tracker: il suo scenario Apple è un
iBeacon classico (`0x004C` tipo `0x02`), che etichettiamo ma non marchiamo
come 👻. Non copre Continuity popup `0x07`, Find My `0x12`, Swift Pair,
Samsung EasySetup, Tile/Chipolo/Pebblebee. Alternative deterministiche per
quelle famiglie:

- i test unitari del rilevamento: `cargo test`;
- un tracker vero (AirTag, SmartTag, Tile) a distanza fissa;
- un telefono Android con l'app gratuita **nRF Connect** che pubblicizza un
  advertisement custom con company ID Apple `0x004C` e payload con primo byte
  `0x07` (popup “New Device”) o `0x12` (Find My) → il device compare nei
  filtri 👻 Spam / 🏷 Tracker e come `[SPAM]` nel monitor `--inq`.

## 10. Stato del radio e analisi di presenza

La pagina **📜 LOG RAW** ha tre pannelli che rispondono a una domanda
diversa da "cosa vedo": **posso fidarmi di quello che vedo?**

### Stato del radio

La prima riga della pagina RAW dice se l'osservazione è affidabile:

| Stato | Significato |
|---|---|
| `attivo` | l'adapter produce pacchetti BLE, quello che manca è dei dispositivi |
| `canale LE muto` | adapter aperto ma il canale non produce da oltre 20 s |
| `adapter assente` | nessun pacchetto BLE mai visto in questa sessione |

Quando lo stato non è `attivo`, sotto compare un avviso: *«l'osservazione non
è affidabile: ciò che manca può essere il radio, non i dispositivi»*.

Questo non è un dettaglio teorico. Un dongle Realtek su VM con passthrough USB
perde il canale LE a intermittenza: senza questa distinzione, un guasto
dell'adapter si presenterebbe come una casa piena di dispositivi improvvisamente
scomparsi.

### Dispositivi spariti

Un MAC compare nella tabella **Spariti** quando l'abbiamo visto almeno
`min_packets` volte (default 3) e non lo vediamo da `silent_minutes` (default
10). Ogni riga mostra ultimo RSSI, quando l'abbiamo visto l'ultima volta, e il
**motivo** (passa il mouse sulla riga).

Parametri via API:

```bash
# 20 minuti di silenzio, almeno 5 pacchetti per considerare noto un device
curl "http://127.0.0.1:9000/api/presence?silent_minutes=20&min_packets=5"
```

Cosa questo pannello **non** fa, di proposito:

- **non conta quanti dispositivi ci sono** — non è deducibile da un'osservazione
  passiva, e un numero sbagliato su un tema di privacy è una bugia utile solo a
  chi sbaglia;
- **non segnala cambi di cadenza**. Misurata sui dati reali, la mediana degli
  intervalli di un singolo iPhone passa da 5,18 s a 0,95 s in otto minuti senza
  che il dispositivo cambi comportamento: è il controller che perde pacchetti.
  Un allarme su quello si sarebbe acceso cinque volte in una sessione.

### Stesso valore Apple Continuity

Il record AD `0x16` sotto UUID FCF1 o FEF3 contiene un valore che Apple deriva
per dispositivo e **tiene costante**: è quello con cui il device legittimo viene
riconosciuto, quindi non può cambiare a ogni rotazione di MAC senza spezzare il
collegamento col telefono.

Il pannello raggruppa i valori comparsi sotto più indirizzi, e la tabella
"Per dispositivo" mostra un badge `↻N` (N = sotto quanti indirizzi è comparso).
Misurato su 4668 pacchetti reali: **17 valori su 55 compaiono sotto più di un
indirizzo**, uno sotto 11.

> Il badge dice **«lo stesso valore è comparso sotto N indirizzi»**, non «sono lo
> stesso dispositivo». Le righe non vengono mai fuse: l'utente che vede 7
> AirTag deve poter continuare a vederne 7. Può anche darsi che due dispositivi
> distinti abbiano lo stesso valore (una flotta di iPhone aziendali, per
> esempio), e in quel caso sarebbero davvero due.

## 11. Deploy su un'altra macchina

Vedi [`deploy/README.md`](deploy/README.md). In breve: l'agente accetta solo un
manifest `{url, sha256}` (mai un binario), verifica l'hash e fa **rollback
automatico** se la nuova build non risponde entro 10 secondi.

```bash
# verifica dell'agente (sintassi, rifiuto hash, rollback, nessun rollback spurio)
powershell -NoProfile -ExecutionPolicy Bypass -File deploy/test-agent.ps1
```

## 12. Condivisione in rete

Il pulsante **🌐 Condividi** in alto a destra fa tre cose insieme: espone la
dashboard su tutte le interfacce, apre la porta nel firewall e salva la scelta,
così al prossimo avvio la condivisione si riaccende da sola.

- `GET /api/share` — stato: `active`, `addresses`, `mdns`, `firewall`.
- `POST /api/share {"on":true}` — accende o spegne. Salva in `share.json`
  accanto all'eseguibile.

Il pulsante ha due comportamenti: **da spento accende**, **da acceso mostra i
dettagli** (indirizzi, mDNS, firewall) con il link per copiare. Se il click
spegnesse direttamente, chi cerca solo l'indirizzo da copiare chiuderebbe la
condivisione per sbaglio.

Due limiti dichiarati:

- **Aprire il firewall richiede diritti di amministratore.** Se mancano, la
  dashboard resta condivisa sul bind `0.0.0.0` ma la porta è filtrata: il
  pannello lo dice e mostra il comando `netsh` esatto da eseguire. Non
  finge di aver aperto nulla. Perché non basti un messaggio dentro la modale —
  che l'utente può chiudere senza leggerla — quando il firewall blocca la
  condivisione compare anche una **striscia arancione in cima alla pagina**,
  che resta finché il problema c'è. Il sintomo che l'utente nota ("non riesco
  a collegarmi dal telefono") è diverso da quello mostrato nella modale, quindi
  l'avviso deve essere visibile senza nessuna interazione.
- **Spegnere la condivisione rimuove la regola del firewall.** Una porta
  lasciata aperta dopo aver spento la condivisione sarebbe una sorpresa.
- **La condivisione sovrascrive `--dashboard-addr`.** Il tasto accende il
  bind su `0.0.0.0` e spegnendo torna a `127.0.0.1`, indipendentemente
  dall'indirizzo passato all'avvio: un IP scelto a mano vale finché la
  condivisione resta spenta. Motivo: l'utente che attiva "Condividi" vuole
  raggiungere la dashboard da qualunque interfaccia, non da una sola.

La riapertura del server richiede ~700 ms: il bind non è modificabile a caldo,
quindi il processo si riavvia e la pagina si ricarica da sola.

## 13. Perdita di collegamento con il server

Se il server smette di rispondere, la dashboard **lo dichiara**:

- la **spazzata rossa del radar si ferma** — continuerebbe a simulare una
  lettura dal vivo che non esiste più;
- i pallini diventano grigi (`.radar-frozen`): i dati sono vecchi, e mostrarne
  i colori veri sarebbe mentire;
- compare una **barra rossa in alto**: "⛔ Non più collegato al server" con
  l'ora dell'ultimo dato ricevuto;
- sul radar appare "Non più collegato al server" con lo stesso orario;
- il pallino di stato diventa rosso e la scritta passa a "Non collegato".

**Non lampeggia.** Serve **due fallimenti consecutivi** (intervallo 5 s) prima
di dichiarare la disconnessione: un singolo errore è quasi sempre una richiesta
lenta, non un server spento. Lampagneggiare a ogni scatto lento renderebbe
l'avviso inaffidabile.

Al ritorno del server tutto si ripristina da solo al primo aggiornamento
riuscito: banner, sovrapposizione sul radar e colori dei pallini.

Nota: `x2`/`y2` della spazzata restano congelati sull'ultimo angolo, così si
vede **dove** si è fermata. La linea non viene cancellata.
