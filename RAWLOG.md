# Log RAW — guida per chi fa reverse engineering BLE

Questa guida è per il target giusto di `bluesniff`: chi sviluppa firmware BLE,
chi studia la privacy dei tracker, chi fa security research. Se ti serve solo
"quali dispositivi ci sono", la dashboard normale basta; qui si parla di
**pacchetti**, non di dispositivi.

## Cosa registra (e cosa no)

Il log raw (`raw_log.jsonl` accanto all'eseguibile) scrive **un record per
pacchetto ricevuto**, non per dispositivo e non per finestra di scansione.
Ogni riga ha:

| Campo | Significato |
|---|---|
| `ts` | timestamp UTC **al millisecondo**, preso dall'orologio del controller (non dall'ora di ricezione del PC) |
| `mac` | indirizzo del device |
| `addr_type` | `public` o `random` — i MAC `random` sono quasi sempre diversi da quelli dichiarati sull'etichetta del prodotto |
| `adv_type` | `connectable`, `non_connectable`, `scan_response`, … |
| `rssi` | dBm come riportati dal controller |
| `connectable` | bit LE General Discoverable dei Flags |
| `scan_response` | vero se il pacchetto è la risposta alla nostra SCAN_REQ |
| `name`, `vendor`, `hint` | arricchimenti: Local Name, company dal manufattore, famiglia del protocollo |
| `model_id` | Google Fast Pair Model ID (3 byte), identifica il modello esatto |
| `tx_power` | Tx Power Level AD (0x0A) o measured power iBeacon |
| `hex` | **i record AD completi** in forma `[len][type][data]` |
| `decode` | un elemento per record AD, leggibile |

**Cosa non c'è, e non può esserci**: bluesniff usa il watcher WinRT, che vede
solo la **publicità** (advertising). I dati successivi a una connessione GATT
o ATT non passano qui, e non è un limite implementativo dell'app ma del
modello di accesso del sistema operativo. Per sniffare il traffico connesso
serve hardware dedicato (nRF Sniffer, Bluefruit) e non un dongle Windows.
L'hex registrato è **ciò che Windows ha consegnato al watcher**: se il
controller filtra o tronca un payload, quel byte qui non compare.

## Protocolli decodificati

I tipi AD standard sono già nel `decode` (Flags, Local Name, Tx Power,
Service Data, Appearance). In più vengono interpretati i protocolli che si
incontrano davvero in città:

- **Apple Continuity** (manufacturer `0x004C`): AirDrop, Nearby Info/Action,
  AirPods, AirPlay, Handoff, MagicSwitch, Tethering, Watch/HomeKit, iCloud
  Phone e **Find My** (`0x12`), con i campi flags e batteria.
- **Google Fast Pair** (manufacturer `0x00E0` e service data `0xFE2C`): il
  Model ID con il **nome del modello** risolto dal database
  `fastpair_models.txt` accanto all'eseguibile.
- **Samsung SmartTag / Find My Mobile** (service data `0xFD5A` con maschera
  `0xF8` e prefisso `0x10`): livello batteria e stato del tag.
- **Eddystone** (service data `0xFEAA`, frame `0x10`/`0x20`/`0x30`): UID,
  **URL ricostruito** (gli schemi sono già sostituiti: `https://…`) e TLM con
  tensione, temperatura e contatore annunci.
- **Google Find My Device Network** (`0xFEAA` frame `0x40`/`0x41`): distingue
  il frame `0x41`, quello con **protezione anti-stalking** (MAC fissa 24h).
- **iBeacon** (`0x004C` + `0x02 0x15`): UUID, major, minor, measured power.
- **Chipolo** (`0xFE33`), **Pebblebee** (`0xFA25`), **Samsung tag** (`0xFE91`),
  **Tile** (`0xFEED`).

## Le statistiche per dispositivo

Nella pagina 📜 LOG RAW, il pannello **Per dispositivo** risponde alle
domande che ti fai guardando i pacchetti:

- **PKT** — quanti pacchetti ha mandato il device nella finestra scelta
- **RSSI min/avg/max** — il segnale peggiore serve per capire quanto è lontano
- **CADENZA med/p95** — l'intervallo mediano e il 95° percentile fra pacchetti.
  È la **firma del protocollo**: un AirTag tipico gira su ~2s, un beacon
  Eddystone TLM su 10s, uno spammer su 20ms. Un P95 molto sopra la mediana
  indica che il device cambia ritmo (tipico: si muove, o è in modalità diverse)
- **PAYLOAD** — quanti payload distinti. Più di uno = il contenuto cambia
  (contatore, stato, rotazione di codice)

Cliccando una riga imposti il filtro della tabella su quel MAC, e il link si
aggiorna con `#raw-mac=AA:BB:CC:DD:EE:FF`: puoi **salvarli e riaprirlo** con
la vista già pronta, o mandarlo a un collega.

## Export

Tutti gli export rispettano l'intervallo **da / ad adesso** che trovi in
alto nella pagina.

### CSV — per Excel
Separatore `;`, una colonna per campo, campi con `;` o virgolette quotati in
stile CSV standard. Pronto per pivot e tabelle.

### JSONL — per scripting
Le righe esattamente come sono nel log: un oggetto JSON per riga, ideale per
`jq` e per rielaborazioni.

```bash
# Solo i pacchetti Apple
jq 'select(.vendor=="Apple") | {ts,mac,hex,decode}' raw_log.jsonl

# I payload che cambiano nel tempo (possibile rotazione/cambio stato)
jq -s 'group_by(.mac)[] | {mac: .[0].mac, distinti: (map(.hex)|unique|length)}' raw_log.jsonl

# La cadenza di un MAC specifico
jq -r 'select(.mac=="AA:BB:CC:DD:EE:FF") | .ts' raw_log.jsonl
```

### PCAPNG — per Wireshark
Il formato che chi fa reverse engineering usa davvero. Il file si apre
direttamente in Wireshark/tshark/CloudShark **senza plugin**: è un pcapng
standard con linktype **251 (BLUETOOTH_LE_LL)**, lo stesso usato dall'nRF
Sniffer, quindi Wireshark disserta le AD structure con i suoi dissector
nativi.

Ogni pacchetto è un Enhanced Packet Block con una **PDU pubblicitaria BLE
 completa** (senza preambolo), cioè esattamente ciò che l'nRF Sniffer mette
 nel pcapng:

- `Access Address` pubblicitario `0x8e89bed6`, quello che Wireshark usa per
  riconoscere il canale ADV;
- header con il **PDU type** reale (ADV_IND, ADV_NONCONN_IND, ADV_SCAN_IND,
  SCAN_RSP) e il bit **TxAdd** (indirizzo random o pubblico);
- campo Length, indirizzo **AdvA** in little-endian, record AD, CRC;
- un **commento pcapng** per pacchetto con RSSI, canale, tipo di indirizzo e
  tipo di annuncio — il linktype 251 non ha un campo RSSI, quindi lo
  portiamo lì (visibile in Wireshark nella colonna Comment e in
  `frame.comment`).

Il CRC è azzerato perché il controller WinRT non ce lo consegna: Wireshark
segnala `Incorrect CRC` su ogni pacchetto, è atteso e non invalida la
decodifica delle AD structure.

```bash
tshark -r bluesniff-raw-....pcapng -V          # dettaglio completo per pacchetto
tshark -r file.pcapng -T fields -e btle.advertising_address \
                             -e btcommon.eir_ad.entry.type \
                             -e frame.comment
tshark -r file.pcapng -Y 'btcommon.eir_ad.entry.type == 0x09'   # solo nomi
```

Verificato con **TShark 4.6.9** su una cattura reale di 4668 pacchetti:
indirizzo, Flags, Manufacturer Specific con Company ID e UUID vengono
dissertati nativamente, zero pacchetti malformati.

Questo ti permette di confrontare **fianco a fianco** una cattura di
bluesniff con una di nRF Sniffer sulla stessa banda, che è il modo standard
per validare che stai davvero vedendo quello che pensi.

## Correlare MAC rotanti

Un trucco utile: i device che fanno privacy by design (AirTag con
anti-stalking, Chipolo ONE, Pebblebee Find My) cambiano MAC o addirittura lo
fisso ogni 24h. Il campo `hint` ti dice la **famiglia del protocollo**: due
MAC con lo stesso `hint` e lo stesso fingerprint sono quasi certamente lo
stesso dispositivo fisico. Le analisi automatiche di questa correlazione sono
già in `--patterns` e `--static` (report dei falsi positivi ambientali con
raggruppamento per fingerprint), che scrivono su `presenze.csv`; il log raw ti
dà il perché a livello di singolo pacchetto.

## Indice dei file prodotti

| File | Contenuto |
|---|---|
| `raw_log.jsonl` | log attivo, ruota a 64 MB |
| `raw_log.<dataora>.jsonl` | chunk ruotati, tenuti 7 giorni |
| `bluesniff.log` | log operativo dell'app |
| `presenze.csv` | presenze per dispositivo (log separato, non per pacchetto) |
| `fastpair_models.txt` | database Model ID → nome modello |
| `bt_known.txt` | i telefoni noti per le probe attive |

Il registro si accende e spegne dalla dashboard (pulsante **⏸ Disattiva
log**) o da riga di comando con `--no-rawlog`.
