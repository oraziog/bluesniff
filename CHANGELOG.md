# Changelog

Tutte le modifiche notevoli a questo progetto sono documentate in questo file.

Il formato si ispira a [Keep a Changelog](https://keepachangelog.com/it/1.1.0/),
e il progetto aderisce al [Semantic Versioning](https://semver.org/lang/it/).

## [0.1.0] - 2026-09-30

Prima versione pubblica. bluesniff ascolta gli annunci BLE e interroga i
telefoni che segui via Bluetooth Classic, e produce tre cose: una dashboard
in locale, un report HTML da condividere, e notifiche sul telefono.

Il progetto deriva da uno scanner Bluetooth one-shot di 0x646e73 (MIT), che
qui e' stato riscritto: non e' la stessa linea di codice, quindi la
cronologia di quel progetto non viene riportata come se fosse nostra.

### Aggiunto

- **bluesniff ora si controlla anche senza stdin.** I comandi `q`, `stop`,
  `start` arrivano dalla tastiera solo quando c'è un terminale: da un `.bat` con
  doppio clic, da Task Scheduler, da un servizio Windows, da SSH non
  interattivo o come sottoprocesso di un orchestratore, stdin non è un
  terminale e quei comandi non arrivavano mai. L'unico modo per fermarsi era
  `taskkill /F`, che tronca `presenze.csv`. Un `--listen` in esecuzione scrive
  ora il proprio PID in `bluesniff.pid` e accetta comandi da fuori con due
  canali: HTTP su `127.0.0.1` (immediato) e un file `bluesniff.ctl` letto ogni
  secondo (universale, senza porte né permessi). I nuovi flag sono
  `--status`, `--pause`, `--resume`, `--stop` e `--snapshot`; senza un processo
  attivo danno un messaggio e codice 1, così uno script fallisce se il fermo
  non è avvenuto. Un PID file orfano di un `taskkill /F` non blocca più
  l'avvio successivo. Con `--dashboard` non parte un server secondo: la sua
  porta viene riusata, e la dashboard ha tre endpoint nuovi
  (`/api/scan/stop`, `/api/scan/status`, `/api/scan/snapshot`) e un pulsante
  **⏹ Ferma bluesniff** nel pannello Radio. Canale e file sono descritti nel
  README, sotto "Controllare bluesniff da un altro processo".

- **Le tre scelte su un dispositivo: Segui / Ignora / Sono io.** Fino ad ora
  dalla dashboard si poteva solo *seguire* un dispositivo (aggiungerlo a
  `bt_known.txt`). Manqueva tutto il resto, e per un utente reale è la parte che
  pesa di più: oggi 200 dispositivi in tabella, di cui 150 non gli interessano e
  uno è il suo telefono. Nella scheda di ogni dispositivo ci sono ora tre
  pulsanti, con la spiegazione di quello che stanno per fare:
  - **🔇 Ignora** scrive in `ignore.txt` (un MAC per riga). Il dispositivo
    sparisce dalla tabella, dai conteggi e da tutti i filtri, e vale ai prossimi
    avvii. Il filtro **Ignorati** e il pannello **Gestisci ignorati** (rimuovi
    uno, o svuota tutto) sono l'unico modo per ritrovarlo. `--ignore`,
    `--unignore`, `--unignore-all`, `--list-ignored` da riga di comando.
  - **👤 Sono io** scrive in `is_me.txt` (un solo MAC: sceglierne un altro
    sostituisce il primo, e la UI dice quale era) e tiene quel dispositivo in
    cima alla tabella in ogni filtro. Non cambia le notifiche: un "sono io"
    silenziato sarebbe una sorpresa, e chi vuole silenziare il proprio telefono
    lo ignora, dove il significato è chiaro.
  - L'**ignora non tocca le notifiche**: sono due file separati perché "non
    voglio vederlo" e "voglio le notifiche" sono due desideri separati. Se
    ignori un dispositivo che stai seguendo, la UI te lo dice e ti chiede se
    vuoi togliere anche il follow — ma non lo fa al posto tuo.
  - I dispositivi ignorati **non contano** in `total` né nelle classi (un numero
    che conta cose invisibili mente); sono contati a parte in `counts.ignored`.
    `GET /api/devices?include_ignored=0` li esclude anche dal corpo, per le
    installazioni con molti dispositivi nascosti.
  - La scheda avvisa quando segui un **MAC BLE randomizzato**: il follow si
    salva e la stella compare, ma il probe Classic non lo raggiunge e quindi non
    arriveranno notifiche. Non proviamo a convertire BLE → Classic (è
    impossibile: l'indirizzo vero non è in nessun annuncio), diciamo il fatto e
    rimandiamo a `--learn`.

- **Comandi da riga di comando per le scelte dei dispositivi**:
  `--follow <MAC> [--name <nome>]`, `--unfollow <MAC>`, `--list-followed`.
  Stessi file della dashboard, quindi utili per scripting e per quando la
  dashboard non è accesa.

- **`bluesniff --doctor` controlla anche `ignore.txt` e `is_me.txt`**: righe non
  MAC nella lista degli ignorati, e un `is_me.txt` con più di un MAC (che è
  ambiguo: vale solo il primo). Nessun `--fix` per questi due file: sono
  facoltativi e nascono col primo uso.

- **Le scritture che riscrivono un file sono ora atomiche** (temporaneo +
  rename). `unfollow` e `unignore` aprivano il file in troncatura: se il
  processo fosse morto a metà, `bt_known.txt` o `ignore.txt` sarebbero rimasti
  a metà, con la lista dei dispositivi persa.

- **La dashboard ora si accende da sola con `--listen`**: `--listen` senza
  `--dashboard` scriveva solo su `presenze.csv` e sul log, e l'utente non
  aveva modo di sapere che esisteva una dashboard. Ora parte da sola quando
  c'è un terminale e non si sta trasmettendo dati (`--json`/`--push` restano
  senza dashboard: sono sottoprocessi di netmonloc, e aprire una porta lì
  sarebbe una scelta invisibile a chi ha lanciato il comando). `--no-dashboard`
  per spegnerla. La riga "dalla dashboard" del banner di bootstrap ora compare
  solo se la dashboard è davvero aperta.

- **Legenda "❓ Come leggere questa dashboard"**: la pagina usava termini
  propri (rotanti, phantom, tracker, phi) spiegati solo in tooltip che l'utente
  non trova. Ora un pannello li spiega in chiaro, e si **apre da solo alla
  prima visita** invece di aspettare che l'utente cerchi un pulsante di cui
  non sa l'esistenza. Dopo si richiama col tasto `h`.

- **`bluesniff --doctor`**: la diagnosi che l'utente può fare da solo. Verifica
  radio, pacchetti BLE, dashboard, firewall della condivisione, `bt_known.txt`,
  `names.txt` e file temporanei, e stampa per ogni problema il comando per
  risolverlo. Con `--fix` applica i rimedi automatici **sicuri** (crea i file
  mancanti, cancella i `.tmp` orfani); `--fix-dry-run` mostra cosa farebbe
  senza toccare nulla. Non apre mai il firewall, non resetta la radio, non
  modifica file che esistono già: sono decisioni dell'utente, non fix.

- **⭐ Segui direttamente dalla dashboard**: non serve piu' aprire
  `bt_known.txt` a mano, scoprire il MAC nella tabella, riavviare `--listen`.
  Ogni scheda dispositivo ha un pulsante che scrive o rimuove la riga, con
  la stella che compare subito. L'editing del file e' preservante: commenti,
  righe vuote, ordine e persone gia' assegnate non vengono mai riscritti.

- **La scheda mostra di chi e' il dispositivo**: un badge con la **Persona**
  letta da `bt_known.txt`, accanto al pulsante Segui. "Di chi e' questo
  telefono" e' l'informazione per cui l'utente tiene questa lista, e prima
  esisteva solo dentro il file di testo. La Persona e' mostrata in dashboard e
  nel log: le notifiche usano il Nome, perche' ntfy le mostra a schermo
  intero e un nome proprio li' dentro e' solo rumo.

- **`bluesniff --edit-known`**: apre `bt_known.txt` nell'editor di sistema
  (creandolo con l'intestazione se non esiste). Il file puo' stare in una
  cartella dove l'utente non ha idea di cercarlo.

- **Il bootstrap di `bt_known.txt` ora si annuncia**: al primo `--listen` il
  file viene creato pieno di MAC senza nome, e senza un messaggio a schermo
  l'utente non ha modo di sapere che quel file esiste e cosa farne. Ora un
  riquadro in console spiega le tre vie (pulsante Segui, editor, `--edit-known`).

- **Il filtro "Seguiti" a zero si spiega da solo**: mostra un riquadro che
  dice come accenderlo. Un contatore vuoto senza istruzioni non e' un aiuto.

- **`bt_known.txt` viene riletto mentre `--listen` gira** (ogni 30 s,
  confrontando la data di modifica): un dispositivo seguito dalla dashboard
  entra nel probe attivo senza riavvio.

- **`--ntfy-absence <N>`**: quanti cicli di scansione consecutivi senza presenza
  servono prima di un avviso "dispositivo uscito" (default 3, prima cablato nel
  sorgente).

- **Ogni blocco `unsafe` deve documentare la sua sicurezza**: attivo
  `#![warn(clippy::undocumented_unsafe_blocks)]` e
  `#![warn(clippy::missing_safety_doc)]`, e ho completato i commenti `SAFETY:`
  mancanti in `btclassic.rs`, `lan.rs`, `radio.rs`.

- **RAW Log Pro: strumenti per reverse engineering BLE**: il log raw esce
  dalla sola "vista dei pacchetti" e diventa un banco di lavoro per chi
  sviluppa firmware e fa ricerca sulla privacy dei tracker.
  - **Statistiche per dispositivo** (`GET /api/raw/stats`, pannello "Per
    dispositivo" nella pagina RAW): pacchetti per device, RSSI
    min/medio/max, **payload distinti** e la **cadenza** (intervallo mediano e
    P95 tra pacchetti), che è la firma del protocollo (un AirTag gira su ~2s,
    uno spammer su 20ms). Click su una riga per filtrare, e il filtro finisce
    nel link (`#raw-mac=...`) per essere salvato e riaperto.
  - **Deep decode dei protocolli proprietari**: Apple Continuity (AirDrop,
    Nearby, AirPods, AirPlay, Handoff, MagicSwitch, Tethering, Watch, Find My)
    con flags e batteria; Google Fast Pair con **nome del modello** risolto dal
    DB `fastpair_models.txt`; Samsung SmartTag/FMM con batteria e stato;
    Eddystone UID/URL (**URL ricostruito**)/TLM con temperatura e contatore;
    Google Find My Device Network che distingue il frame `0x41` di
    **protezione anti-stalking**; piu Chipolo, Pebblebee, Tile, Samsung tag.
  - **Export PCAPNG**: nuovo formato `format=pcapng` nell'export per
    intervallo. Genera un pcapng standard (linktype 251 BLUETOOTH_LE_LL, lo
    stesso dell'nRF Sniffer) che si apre in Wireshark/tshark/CloudShark senza
    plugin, con pseudo-header BLE LL (RSSI signed, canale) e record AD
    dissertati dai dissector nativi — per confrontare una cattatura bluesniff
    con una di nRF Sniffer sulla stessa banda.
  - **RAWLOG.md**: guida dedicata al target giusto (anatomia del record,
    protocolli decodificati, esempi Wireshark e `jq`, correlazione dei MAC
    rotanti), con l'avvertenza esplicita che il watcher WinRT vede solo la
    pubblicità e che per il traffico connesso serve uno sniffer dedicato.
  - Correzione: la mediana della cadenza ora è la media dei due valori
    centrali quando i campioni sono in numero pari (prendeva il secondo, che
    falsava la lettura).
  - Correzione: **la ricerca nei pacchetti ora gira sul server** e rispetta
    l'intervallo da/ad. Prima la tabella mostrava solo gli ultimi 300
    pacchetti del file mentre le statistiche aggregavano tutto: cliccando un
    dispositivo che non era nella coda (la maggior parte, con decine di device
    in zona) non compariva pacchetti, sembrando un dispositivo fantasma.

- **Log raw per-pacchetto con esadecimale e decodifica**: ogni annuncio BLE
  ricevuto viene registrato in `raw_log.jsonl` (accanto all'eseguibile) con
  timestamp al millisecondo, MAC, tipo di indirizzo (public/random), tipo di
  annuncio (connectable/scan_response/…), RSSI, payload AD completo in hex
  (`[len][type][data]`, fedele a ciò che Windows consegna al watcher) e la
  decodifica leggibile dei record AD (Flags, nomi, Tx Power, Service Data,
  Manufacturer con vendor, iBeacon con UUID/major/minor, Fast Pair Model ID).
  Attivo di default in `--listen`/`--record` (e `--track`/`--classify`);
  `--no-rawlog` lo disattiva. Il file ruota a 64 MB in
  `raw_log.<dataora>.jsonl` con retention di 7 giorni. Scrittura non
  bloccante: a coda piena i pacchetti sono contati come scartati, mai
  rallentata la scansione. La dashboard ha una nuova pagina **📜 LOG RAW**
  (pannello Radio) con live view filtrabile, interruttore on/off a runtime e
  **export per intervallo data-ora → data-ora/adesso** in CSV (Excel-ready) e
  JSONL (fedele al log). Nuovi endpoint: `GET /api/raw`, `POST
  /api/raw/enable`, `POST /api/raw/disable`, `GET /api/raw/export`.

- **Selezione della radio con `--radio <indice|MAC|nome>`**: l'enumerazione
  degli adattatori ora espone un indice 1-based (lo stesso del banner di
  avvio) e il selettore accetta indice, MAC (in qualunque formato) o nome,
  con errore leggibile + elenco delle radio disponibili se non corrisponde
  nulla. La scelta è applicata dove lo stack la rispetta davvero: l'inquiry
  Classic parte dalla radio scelta (`hRadio` in
  `BLUETOOTH_DEVICE_SEARCH_PARAMS`) e le probe RFCOMM legano il socket
  all'adattatore locale (`bind` su AF_BTH). Il watcher BLE di WinRT
  scansiona per forza l'adattatore predefinito di sistema: quando la radio
  scelta non è quella, bluesniff lo dichiara a voce alta (banner + log)
  invece di far credere che la scansione LE la stia usando.

- **Reset della radio (`--reset-radio [secs]`)**: spegne e riaccende la
  radio Bluetooth via WinRT (`Radio::SetStateAsync`) per recuperare uno
  scanner LE muto (0 pacchetti con radio accesa) senza riavviare il PC.
  Disponibile anche dalla dashboard (pulsante **⟳ Reset radio** nel pannello
  Radio, `POST /api/radio/reset`), che riporta l'esito e poi riprende da
  sola; un rifiuto del sistema è un messaggio, mai un panic. Il pannello
  Radio ora mostra anche **🎯 Radio attiva**, cioè la radio scelta.

- **Marcatori falsi positivi nel console di `--listen`**: la riga
  `listen sample` ora mostra gli stessi flag della dashboard —
  `| 📌 MAC` per i dispositivi statici (varianza RSSI < 4.0 su >= 5
  campioni) e `| 🔄N MAC` per le famiglie di MAC rotanti (stesso
  fingerprint su N indirizzi).

- **Database nomi GATT (SIG/blecat)**: la Sonda GATT ora usa il dataset
  ufficiale Bluetooth SIG importato da blecat (`services.yaml` +
  `characteristics.yaml`): 83 servizi e 504 characteristic con nome
  leggibile accanto a ogni UUID scoperto (es. "Battery Service", "Heart
  Rate", "Battery Level"), più gli alias vendor (Fast Pair, Tile, Nordic
  UART, Samsung, Xiaomi, Apple Continuity). Il dataset SIG corregge anche
  etichette sbagliate della vecchia mappa embedded (es. 0x1814 è "Running
  Speed and Cadence", non "Alert Notification"; la lettura Device
  Information è stata ristretta agli UUID ufficiali).

- **Banco di prova BLE_HackMe**: nuova sezione in README-DASHBOARD.md
  (sez. 9) che spiega come usare il simulatore BLE di smartlockpicking
  (Microsoft Store o build Visual Studio) per testare in modo
  deterministico scoperta BLE, radar/RSSI, marcatura 📌 statico e
  Sonda GATT.

- **Il report HTML: un file da condividere.** La dashboard e' uno strumento,
  serve mentre ascolti; il report e' l'artefatto. `bluesniff --report` scrive un
  unico file `.html` autonomo — niente JavaScript, niente risorse esterne, niente
  rete — che si apre in qualsiasi browser, anche offline e su un telefono, e si
  stampa su A4 con i colori corretti. Contiene intestazione (stazione e
  intervallo), un sommario in linguaggio naturale, le cifre in evidenza, la
  timeline dei dispositivi seguiti con i pattern, la heatmap oraria 24×7, gli
  eventi notevoli (CVE, localizzatori, rotazione di MAC, prime apparizioni) e
  l'appendice con la tabella completa. Opzioni: `--report-last 24h`,
  `--report-from`/`--report-to`, `--report-output`, `--report-anonymize` (i MAC
  diventano `AA:BB:CC:XX:XX:XX`), `--report-no-appendix`, `--report-open`.
  Stesso report dal bottone **📄 Report HTML** in dashboard e da
  `GET /api/report`, che risponde con `Content-Disposition: attachment` e gira in
  `spawn_blocking` per non bloccare il runtime.

  Sul cosa il report *non* dice: non dice dove era un dispositivo (il radio sente
  la forza del segnale, non la posizione), non afferma che qualcuno ti sta
  seguendo, e non dichiara un "tempo di presenza" che dai dati istantanei non
  esiste: dice finestra, visite e avvistamenti, tre cose che si possono contare.

- **Notifiche verificabili in un click: «📤 Invia notifica di test».** Il
  sistema ntfy funzionava, ma era invisibile: nessuno sapeva cosa fosse un
  topic, e l'unico modo di capire se la configurazione era a posto era aspettare
  che un dispositivo seguito arrivasse o se ne andasse. Ora nel modale
  **Notifiche ntfy** c'e' un pulsante che manda una notifica di prova con il
  topic e il server *attualmente scritti nei campi* e mostra l'esito reale:
  verde con la conferma, rosso con il motivo (timeout, connessione rifiutata,
  4xx di ntfy con il corpo del messaggio). Non salva niente: si puo' provare
  un topic prima di adottarlo, e un test fallito non modifica la
  configurazione. Stessa cosa da riga di comando con
  `bluesniff --ntfy-test <topic>` (`--ntfy-server <url>` per un server tuo).

- **Un topic scritto male non veniva segnalato, e il topic non è spiegato.** La
  validazione (1-64 caratteri, solo `[A-Za-z0-9_-]`, niente spazi o slash, e
  server senza barra finale) scatta sia su **Salva** sia sul test, e l'errore
  compare sotto il campo che lo ha causato. Il modale ora spiega cosa sia un
  topic, avvisa che chi lo conosce puo' leggere le notifiche, e contiene un
  riquadro «Come funziona ntfy (30 secondi di lettura)» con i cinque passi.

- **Il README non spiegava le notifiche.** La sezione «Seguire un dispositivo»
  aveva tre righe di setup. Ora ha «Configurare ntfy (5 minuti)» con
  installazione dell'app, scelta del topic, i tre motivi per cui una
  notifica apparentemente inviata non arriva (topic diverso nell'app con
  maiuscole diverse, notifiche del telefono silenziate, dispositivo non in
  `bt_known.txt`), il server self-hosted e cosa esce dal PC.

- **La dashboard si usa davvero dal telefono.** Era raggiungibile (basta
  `--dashboard-addr lan`) ma illeggibile: tabella a sette colonne, sidebar dei
  filtri nascosta sotto i 900 px, radar con etichette di tre pixel. Sotto i
  700 px la tabella diventa una lista di card (nome, MAC, vendor, RSSI, ultimo
  contatto in pila, con l'intera card cliccabile) e i filtri ricompaiono come
  chip scorrevoli in cima alla lista, con i conteggi presi dagli stessi
  elementi della sidebar — due copie dei numeri divergerebbero alla prima
  esecuzione. Il layout si ricostruisce da solo ruotando il telefono, e su
  mobile la pagina mostra 20 dispositivi invece di 50. I modali occupano tutto
  lo schermo, i numeri di pagina spariscono (restano «prec»/«succ» e «pagina
  3/12»), l'orario della topbar si ritira per far spazio ai pulsanti. Sul
  radar i puntini passano da 4 a 6 di raggio e le etichette spariscono: a
  quelle dimensioni non si leggono, e il tap apre comunque la scheda.

- **Installabile come app dal telefono.** `GET /manifest.json`, `/sw.js`,
  `/icon-192.png` e `/icon-512.png`, più i meta tag per iOS e Android: da li si
  fa «Aggiungi alla schermata Home» e la dashboard si apre a schermo intero.
  Il service worker è **volutamente vuoto**: i dati cambiano ogni 5 secondi e
  una cache anche minima mostrerebbe uno stato vecchio come se fosse attuale.
  Da segnalare che il prompt automatico di Chrome non compare su `http://` in
  chiaro (lo vuole solo su HTTPS): l'installazione manuale dal menu funziona
  lo stesso, ed è il modo normale su iOS. Le icone sono incluse nel binario:
  un'icona mancante farebbe fallire l'installazione senza che l'utente possa
  accorgersene.

- **Un `--help` che si legge.** Era trenta righe piatte, senza sezioni e senza
  esempi: per un utente che arriva dal README, `bluesniff --help` non diceva
  da dove cominciare, e per uno che aveva gia' il tool in mano serviva
  scorrerlo tutto per ricordare come si scrive `--prune-min-sightings`. Ora ha
  una sezione **USO RAPIDO** con i cinque comandi che coprono il 90% dei casi,
  poi i comandi veri, le opzioni di `--listen`, le notifiche, lo streaming, le
  scorciatoie da tastiera e il report — ognuno sotto un titolo, con i comandi
  in giallo e le descrizioni in colonna. Esiste anche l'**aiuto contestuale**:
  `bluesniff --listen --help` mostra le opzioni di `--listen` e rimanda al
  resto con `bluesniff --help`; stesso discorso per `--inq` e `--report`.
  Aggiunti `--version` / `-V`.

- **`bluesniff` senza argomenti ora apre la dashboard.** Prima faceva uno scan
  BLE di 5 secondi: un comando che si chiude da solo e sparisce e'
  indistinguibile, per chi arriva dal README, da uno che non funziona, e
  l'unico modo di capirlo era digitare `--help`. Ora avvia il monitor
  continuo con la dashboard su `localhost:9000` — e funziona anche senza
  terminale, che e' il caso di chi lo lancia da un collegamento o da un `.bat`.
  Lo scan di 5 secondi c'è ancora, con un nome che lo dice:
  `bluesniff --one-shot`. L'avviso del cambio compare solo se c'e' gia' un
  `presenze.csv` con dati, cioe' solo per chi si accorge di una differenza.

- **Smoothing RSSI (filtro alpha-beta 1-D per dispositivo, idea da
  BTScan/kalman_filter.py di bluetooth-arsenal)**: l'RSSI mostrato e
  salvato nello storico ora passa da un filtro livello+tendenza — i
  tracciati del radar, la zona di prossimità e le distanze stimate non
  saltano più a ogni campione (un singolo campione anomalo viene smorzato
  di ~2/3). Lo storico della scheda e le distanze usano i valori
  stabilizzati.

- **Filtro sidebar "🏷 Tracker"**: mostra solo i dispositivi con annunci
  stile tag/popup — Apple Continuity, Swift Pair, Samsung EasySetup,
  Fast Pair (0xFE2C) e Tile (0xFEED) — con conteggio live (`tracker` in
  `/api/devices`).

- **Riconoscimento Tile**: il service UUID 0xFEED (riferimento
  reelyActive/Sniffypedia) ora marca i tracker Tile come `tile` nel badge
  👻/🏷 della tabella e della scheda.

- **Più famiglie di tracker riconosciute** (firme verificate da AirGuard
  TU Darmstadt e spec Google FHN v1.3): Apple Find My 0x004C/0x12
  (AirTag, Chipolo ONE Spot, Pebblebee Find My → `apple-findmy`),
  Samsung SmartTag 0xFD5A (`samsung-smarttag`, incl. SmartTag+ / 2 /
  Solum), Samsung Find My Mobile 0xFD69 (`samsung-fmm`), Chipolo 0xFE33
  (`chipolo`), Pebblebee 0xFA25 (`pebblebee`) e Google Find My Device
  Network 0xFEAA frame 0x40/0x41 (`google-findmy` — Chipolo One Point,
  Pebblebee, Motorola, Hama, Eufy, Jio, Rolling Square; 0x41 =
  anti-stalking con MAC fisso 24 h). Distinzione pulita da Eddystone
  (0xFEAA primo byte 0x00/0x10/0x20/0x30).

- **Famiglia tracker nel tooltip radar e nella riga tabella**: il tooltip
  del radar mostra il nome specifico (es. "👻 Chipolo tracker") invece
  del generico "phantom"; badge di riga e scheda distinguono tracker
  (titolo "Tracker BLE riconosciuto", etichetta 🏷) dagli annunci
  popup/spoof (titolo "possibile spoof BLE").

- **Filtro sidebar "⚠ Con rischi"**: mostra solo i dispositivi con CVE
  note, annuncio phantom o servizi SDP a rischio di esposizione
  (MAP/OBEX/PBAP) — conteggio live accanto al filtro (`risky` calcolato
  lato server in `/api/devices`).

- **Auto-SDP reattivo**: la sonda SDP sui telefoni noti ora parte anche
  appena il telefono compare nell'inquiry classic (page-scan/discoverable),
  senza aspettare il ciclo di probe attivo dei 60 s; stessa registrazione
  (riga `sdp` in presenze.csv + cache dashboard).

- **Streaming verso netmonloc (integrazione master/slave)**: con
  `--listen --json` bluesniff emette una riga NDJSON per scansione in
  stdout (niente ANSI, niente presenze.csv) e risponde al comando
  `snapshot` letto dallo stdin con lo stato corrente. Il master che
  avvia bluesniff come processo figlio puo consumare i dati via due
  canali. Con `--push` (opzionale `--push-token`) le scansioni vengono
  inviate via HTTP POST/JSON con retry esponenziale e coalescenza delle
  istantanee rimaste in coda; in modalita streaming il file presenze.csv
  non viene scritto (puro streaming). Il pusher gira in un thread
  dedicato con runtime tokio isolato per non interferire col watcher
  WinRT.

- **Filtro falsi positivi ambientali (fpfilter)**: nuova analisi locale
  in stile correlate — un dispositivo e statico quando l'RSSI ha
  varianza sotto 4.0 con almeno 5 campioni (Smart-Tag dietro il muro,
  PC/TV fisso, antenna), e i MAC che ruotano lo stesso fingerprint BLE
  vengono accorpati come un solo dispositivo fisico (con conteggio MAC).
  Applicata dal vivo nella dashboard (badge in tabella, scheda e tooltip
  radar; filtri sidebar Statici e Rotanti con conteggi live) e
  disponibile offline come report: `bluesniff --static [presenze.csv]`
  stampa i falsi positivi e l'accorpamento in bucket di un minuto.

- **Fix runtime di fondo**: corretto il transmute del logger nei task in
  background (spawn_pusher, spawn_heartbeat) che estendeva la vita di un
  puntatore a stack invece che del riferimento — il push HTTP ora
  termina pulito (exit 0) e le righe di log dei task tornano a comparire
  nel file.

### Corretto

- **La pausa della dashboard e quella del canale di controllo erano due flag
  diversi.** Un utente che metteva in pausa dal pannello Radio e poi riprendeva
  da riga di comando restava fermo (o il contrario), e nessuno dei due canali
  spiegava perché: ciascuno leggeva e scriveva il proprio. Ora è un solo flag di
  pausa per processo, e la dashboard cede il suo allo stato condiviso.

- **`bluesniff --status` non ripeteva il PID due volte.** La riga di contesto
  veniva aggiunta dal lato client anche quando la conferma del processo
  conteneva già PID e modalità: due righe identiche in testa all'output
  sembravano due processi in esecuzione.

- **La dashboard poteva diventare "mezza viva" senza errori.** Due difetti dello
  script inline: un apostrofo non escapato in una stringa spegneva lo script
  dalla riga in cui si trovava (nessun errore visibile, la pagina si caricava e
  la lista spariva), e il pulsante di arresto era finito come espressione
  separata dopo il `;` che chiude `innerHTML`, quindi non arrivava mai nel DOM.
  `cargo test` ora valida il blocco `<script>` con `node --check` (salta se
  node non è installato) e verifica che il pulsante sia nella catena che
  costruisce il pannello.

- **La heatmap del report mostrava sette copie dello stesso giorno.** Prendeva il
  conteggio per ora e lo replicava identico sulle sette righe della griglia: una
  sola giornata osservata sembrava una settimana piena, e viceversa una settimana
  vera sembrava piatta. Ora ogni cella vale il suo giorno (griglia 7×24).

- **Il report annunciava "0 pacchetti" per un localizzatore appena identificato.**
  Il conteggio veniva dal raw log, che non copre tutti i MAC; se un dispositivo e'
  presente nel CSV delle presenze ma non nel raw log, la riga diceva zero
  avvistamenti accanto a un titolo che ne annunciava la presenza. Ora il conteggio
  viene dal CSV, e l'hint del raw log fa da piano B quando la colonna del CSV e'
  vuota (un localizzatore riconosciuto non si perde piu' per quello).

- **I pulsanti della scheda dicevano "errore rete" dopo aver scritto il file.**
  Aprendo un dispositivo da un link condiviso (`?device=MAC`) o dalla ricerca,
  quel dispositivo non è nella lista live: il codice passava `undefined` alla
  funzione di ridisegno, l'eccezione finiva nel `catch` e l'utente leggeva
  "errore rete" — mentre l'operazione era riuscita. Ora il ridisegno ricostruisce
  la scheda quando il dispositivo non è in lista.

- **Un link condiviso mostrava una scheda falsa**: per un dispositivo già
  presente in tabella, `?device=MAC` apriva una scheda con zero avvistamenti e
  "non seguito", e i suoi pulsanti avrebbero scritto righe duplicate per un MAC
  già presente. Ora usa il device reale se esiste.

- **`unfollow`/`unignore` con un MAC non valido rispondevano "fatto"**: un
  no-op silenzioso è una risposta falsa, e lascerebbe convinto di aver tolto un
  dispositivo che invece continua a notificare. Ora è un errore esplicito.

- **Un solo posto decide che cos'è un MAC valido**: la normalizzazione esisteva
  in quattro copie (`known.rs`, `radio.rs`, e le due nuove). Copie che
  divergono significa che lo stesso indirizzo può essere accettato da un file e
  rifiutato da un altro, e il sintomo è una riga che sparisce a ogni reload.
  Ora vivono tutte in `fsx.rs`.

- **`--inq --dashboard` non attivava più la dashboard**: il parser dei flag con
  argomento opzionale consumava il token successivo. `--inq` con un flag dopo
  si mangiava `--dashboard` (che finiva come argomento non numerico), quindi la
  dashboard partiva solo se il flag era l'ultimo della riga di comando. Ora il
  parser guarda avanti senza consumare.

- **Nessun `unsafe` per allungare un lifetime**: il logger veniva passato ai
  task come `&'static Logger` ottenuto con `std::mem::transmute`. Ora `Logger`
  è `Clone` e condivide il file handle tramite `Arc<Mutex<File>>`, e i task lo
  ricevono per valore.

- **reqwest fuori dal runtime condiviso**: gli avvisi ntfy e l'heartbeat ora
  girano su thread dedicati con runtime proprio (come il pusher NDJSON),
  perché `reqwest` nel runtime tokio condiviso causava
  `STATUS_HEAP_CORRUPTION` (0xC0000374) con il watcher WinRT. `alerts.update()`
  non è più `async`: accoda e ritorna, il thread dedicato fa le POST.

- **Riavvio della dashboard serializzato**: due click rapidi su "Condividi"
  potevano far fermare due volte il server, colpendo il sender di quello appena
  avviato. Il riavvio ora è protetto da un flag e il bottone è disabilitato
  durante il cambio; il logger viene clonato invece di riaprire il file a ogni
  riavvio.

- **La porta dichiarata è quella su cui si sta davvero ascoltando**:
  `state.set_port()` viene chiamato dopo il bind riuscito, non prima. Se la
  porta è occupata la dashboard lo dichiara e `share` non calcola più un
  indirizzo sbagliato.

- **Firewall non aperto: avviso in barra, non solo nella modale**. Il sintomo
  ("non riesco a collegarmi") è diverso da quello mostrato nel popover che
  l'utente può chiudere senza leggere, quindi ora compare una striscia arancione
  in cima alla pagina finché la condivisione è attiva e la porta filtrata.

- **Cache sonde GATT/SDP con eviction FIFO**: `HashMap::keys()` non ha ordine,
  quindi la cache scartava voci a caso invece delle più vecchie.

- **Aritmetica delle date unificata**: `dashboard.rs` aveva una seconda copia di
  `rfc3339_epoch` e `days_from_civil`; ora delega a `logging.rs`.

- **`is_locally_administered` non inventa più risposte**: un MAC vuoto o
  illeggibile rispondeva "randomizzato", etichettando come privati dispositivi
  sconosciuti. Ora risponde "non lo sappiamo".

- **Indirizzi IP per mDNS**: `local_ip_addresses` usava un socket verso
  8.8.8.8 (richiede connettività Internet) e la risoluzione del nome host
  (dipende da NetBIOS). Ora usa `lan::local_ipv4_addrs()`, che legge la tabella
  IP di Winsock.

- **Esportazione PCAPNG ora realmente apribile in Wireshark**: il writer
  prependeva a ogni pacchetto un pseudo-header di 4 byte (flags/RSSI/canale)
  che non esiste nel linktype 251, quindi Wireshark leggeva rumore e
  riportava `LE LL ... Unknown [Malformed Packet]` su **tutti** i pacchetti.
  Ora ogni pacchetto è una PDU pubblicitaria LL completa — access address
  `0x8e89bed6`, header con PDU type reale (ADV_IND / ADV_NONCONN_IND /
  ADV_SCAN_IND / SCAN_RSP) e bit TxAdd, AdvA little-endian, record AD, CRC —
  esattamente il formato dell'nRF Sniffer. RSSI, canale e tipo di indirizzo
  finiscono nel commento pcapng del pacchetto, dato che il linktype 251 non ha
  campi RF. Validato con TShark 4.6.9 su 4668 pacchetti reali: indirizzo,
  Flags, Manufacturer Specific con Company ID e UUID dissertati nativamente,
  0 pacchetti malformati. L'unico warning residuo è `Incorrect CRC`, atteso:
  il CRC non viene consegnato dall'API WinRT e resta azzerato.

- **Filtri "Ultimi eventi"** (Tutti/Nuovi/Pacchetti/Spariti/Spam):
  gestione click per delega sul contenitore (sopravvive ai re-render),
  rimossa l'icona 👻 da "Spam" e ridimensionate le 5 voci (font/padding)
  così entrano tutte su un rigo nella colonna sinistra senza troncamenti;
  messaggio di stato vuoto ora riporta il filtro attivo.

- **Radar ingrandito**: finestra modale più grande
  (max-width min(96vw,1100px), max-height 96vh, SVG min(88vw,70vh)) —
  niente più scrollbar laterale.

- **Vista compatta della tabella**: il MAC compare prima del nome
  (allineato con le altre righe) invece di "swift-pair AA:BB:...".
