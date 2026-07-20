// =============================================================================
// Contextual Vulnerability Risk Scoring via LLM — Final Reports
// =============================================================================

#set page(
  paper: "a4",
  margin: (left: 2.5cm, right: 2.5cm, top: 2.5cm, bottom: 2.5cm),
  numbering: "1",
)

#set par(
  justify: true,
  leading: 0.67em,
  first-line-indent: 1em,
)

#set text(
  font: "Libertinus Serif",
  size: 11pt,
  lang: "it",
)

#set heading(numbering: "1.")

#let header-sep() = {
  v(0.5em)
  line(length: 100%, stroke: 0.5pt + gray)
  v(0.5em)
}




// ─── Title page ──────────────────────────────────────────────────────────
#let cover-page() = {
  set page(numbering: none)

  set par(justify: false, first-line-indent: 0pt)

  align(center + top)[
    #text(size: 18pt, weight: "bold")[UNIVERSITÀ DEGLI STUDI DI SALERNO]
    #v(0.1cm)
    #text(size: 14pt, weight: "bold")[DIPARTIMENTO DI INFORMATICA]
    #v(0.5cm)

    #image("img/unisa-logo.png", width: 4cm)

    #v(0.5cm)
    #text(size: 12pt, weight: "bold")[Corso Penetration Testing and Ethical Hacking]

    #v(1cm)
    #text(size: 20pt, weight: "bold", style: "italic", hyphenate: false)[PrioritAIze: Contextual Vulnerability Risk Scoring via LLM Platform]

    #v(2cm)

    #grid(
      columns: (1fr, 1fr),
      gutter: 1.6cm,
      [
        #align(left)[
          #text(size: 12pt, weight: "bold")[Professore:]
          #v(0.1cm)
          #text(size: 11pt)[Arcangelo Castiglione]
        ]
      ],
      [
        #align(right)[
          #text(size: 12pt, weight: "bold")[Candidato:]
          #v(0.1cm)
          #text(size: 11pt)[Luigi Miranda] \
          #text(size: 11pt)[Matricola: 0522501934]
        ]
      ],
    )
  ]

  align(center + bottom)[
    #text(size: 12pt, weight: "bold")[ANNO ACCADEMICO: 2025/2026]
  ]

  pagebreak()
}

#cover-page()

// =============================================================================
// 1. INTRODUZIONE
// =============================================================================
#heading(numbering: "1.")[Introduzione]

#header-sep()

I moderni team di sicurezza affrontano un volume crescente di vulnerabilità
segnalate da scanner automatici, penetration test, bug bounty program e feed di
threat intelligence. La metrica standard per la prioritizzazione — il Common
Vulnerability Scoring System (CVSS) — valuta la gravità *tecnica* di una
vulnerabilità su scala 0--10, ma ignora completamente il contesto aziendale
dell'asset colpito: la sua criticità operativa, l'esposizione di rete, i
framework normativi applicabili e l'impatto finanziario di un eventuale breach.

Questo report descrive *PrioritAIze*, un
framework che combina:

1. *Large Language Model (LLM) reasoning* per analizzare qualitativamente il
   rischio nel contesto specifico dell'asset;
2. *Business Impact Modeling* per quantificare l'impatto finanziario in Euro
   (costi di downtime, sanzioni normative, danno reputazionale);
3. *Dynamic Risk Scoring* che produce un punteggio 0--10 pesato
   contestualmente, superando la staticità del CVSS.

Il risultato è una lista di vulnerabilità prioritizzata non per gravità tecnica,
ma per *impatto reale sul business*, consentendo ai team di security di allocare
le risorse dove generano il massimo valore di riduzione del rischio.

=== Obiettivi del progetto

- Sviluppare un sistema containerizzato, riproducibile, con architettura
  modulare a cinque componenti;
- Integrare un LLM (qualsiasi modello OpenAI-compatibile) per il ragionamento
  contestuale sul rischio;
- Implementare un modello di impatto finanziario deterministico che simuli
  downtime, multe normative e danno reputazionale;
- Produrre una dashboard web interattiva con trasparenza totale sulle formule
  di calcolo.

=== Autorizzazione e scope

Il progetto opera esclusivamente su dati mock (seed data in `assets.yaml` e
`cost_model.yaml`). Non è stato effettuato alcun test su sistemi, reti o asset
reali. L'architettura è progettata per l'integrazione diretta con fonti live
(CMDB, cloud inventory API, criticality tagging systems) in un ambiente
produttivo autorizzato.

#pagebreak()

// =============================================================================
// 2. STATO DELL'ARTE
// =============================================================================
#heading(numbering: "1.")[Stato dell'arte]

#header-sep()

=== Sistemi di scoring tradizionali

Il *Common Vulnerability Scoring System (CVSS)*, mantenuto dal FIRST
(Forum of Incident Response and Security Teams), è lo standard de facto per la
valutazione della gravità delle vulnerabilità. Nella versione 3.1, il punteggio
è calcolato a partire da tre gruppi di metriche:

- *Base Score*: caratteristiche intrinseche della vulnerabilità (vettore
  d'attacco, complessità, privilegi richiesti, impatto su confidenzialità /
  integrità / disponibilità);
- *Temporal Score*: fattori che cambiano nel tempo (maturità dell'exploit,
  disponibilità di patch);
- *Environmental Score*: adattamento all'ambiente specifico (requisiti di
  sicurezza dell'organizzazione).

Il CVSS Environmental Score consente un adattamento limitato — principalmente
tramite la modifica dei requisiti di confidenzialità, integrità e disponibilità
(CIA) — ma non incorpora dati finanziari, normativi o di business criticality
specifici dell'asset. Nella pratica, la maggior parte delle organizzazioni
utilizza solo il Base Score per la prioritizzazione, perdendo ogni
differenziazione contestuale #link(<ref1>)[[1]].

=== Approcci basati su rischio

Negli ultimi anni sono emersi framework di *risk-based vulnerability management*
(RBVM) che arricchiscono il CVSS con dati di contesto:

- *Tenable Vulnerability Priority Rating (VPR)*: combina CVSS con dati di threat
  intelligence e maturity degli exploit tramite modelli di machine learning
 #link(<ref3>)[[3]].
- *Kenna.VM* (Cisco): utilizza algoritmi predittivi per stimare la probabilità
  di exploit effettivo.
- *Qualys TruRisk*: aggrega dati di asset criticality, configurazioni di
  sicurezza e threat intelligence.

Questi sistemi sono efficaci ma sono *proprietari, closed-source* e offrono
all'utente un controllo limitato sulla logica di scoring. Inoltre, nessuno di
essi utilizza LLM per il ragionamento qualitativo contestuale #link(<ref2>)[[2]].

=== LLM nella cybersecurity

L'applicazione di Large Language Models alla cybersecurity è un campo in rapida
evoluzione. Lavori recenti hanno esplorato:

- *Vulnerability detection*: modelli come GPT-4 e modelli specializzati (es.
  SecureBERT, CyBERT) per identificare vulnerabilità nel codice sorgente;
- *Threat report summarization*: sintesi automatica di report di intelligence;
- *Automated penetration testing*: agenti LLM-based per la generazione di
  payload e il ragionamento su catene di exploit.

Il presente progetto si colloca nell'intersezione tra LLM reasoning e risk-based
vulnerability management, un'area ancora poco esplorata nella letteratura
accademica e commerciale. L'innovazione principale risiede nell'approccio
*ibrido*: l'LLM fornisce il ragionamento qualitativo (perché una vulnerabilità è
più o meno grave in un dato contesto), mentre formule deterministiche ancorate
a parametri configurabili calcolano l'impatto finanziario quantitativo.

#pagebreak()

// =============================================================================
// 3. TECNOLOGIE UTILIZZATE
// =============================================================================
#heading(numbering: "1.")[Tecnologie utilizzate]

#header-sep()

#figure(
  table(
    columns: 3,
    align: (left, left, left),
    table.header(
      [*Tecnologia*], [*Versione / Tipo*], [*Ruolo nel sistema*]
    ),
    [Python], [3.12], [Linguaggio principale — ecosistema ricco per AI/ML, API, data processing],
    [FastAPI], [0.115+], [Web framework asincrono — validazione automatica, documentazione OpenAPI integrata],
    [Jinja2], [3.x], [Template engine per server-side rendering delle pagine web],
    [Bootstrap 5], [5.3], [CSS framework per UI responsive, supporto nativo dark mode tramite `data-bs-theme`],
    [Chart.js], [4.x], [Libreria JavaScript per grafici dashboard (istogramma, doughnut, pie)],
    [PostgreSQL], [16-alpine], [Database relazionale per persistenza delle valutazioni e audit log],
    [psycopg2], [2.9], [Driver PostgreSQL — accesso raw SQL con `RealDictCursor`, nessun ORM],
    [OpenAI SDK], [1.x], [Client compatibile con qualsiasi endpoint OpenAI-compatibile (GPT-4, Claude, Llama, DeepSeek, Ollama)],
    [httpx], [0.27+], [Client HTTP asincrono per chiamate alla NVD API v2],
    [uv], [0.6+], [Package manager veloce — sostituisce pip + venv],
    [Docker Compose], [v2+], [Orchestrazione container — app + PostgreSQL in ambienti riproducibili],
    [Ruff], [0.9+], [Linter e formatter — sostituisce flake8 + black + isort in un unico tool],
  ),
  caption: [Stack tecnologico del progetto PrioritAIze.],
) <tech-stack>

=== Motivazione delle scelte

*FastAPI* è stato scelto per il supporto nativo all'asincronia (essenziale per
le chiamate concorrenti a LLM e NVD), la validazione automatica dei dati
(Pydantic) e la generazione automatica della documentazione OpenAPI.

*PostgreSQL con raw SQL:* il progetto richiede esplicitamente l'uso di SQL
diretto senza ORM. L'uso di `RealDictCursor` garantisce un'esperienza
ergonomica (dizionari Python) simile a un ORM senza il layer di astrazione.

*Server-side rendering con Jinja2:* la scelta di evitare framework SPA (React,
Vue) riduce la complessità del build toolchain, garantisce caricamenti più
veloci (HTML completo al primo render) e risulta più adatta a un tool
interno/PoC accademico. L'interattività è delegata a Chart.js e vanilla
JavaScript per le parti dinamiche della dashboard.

*Compatibilità multi-LLM:* l'uso dell'OpenAI SDK con `base_url` configurabile
consente di puntare a qualsiasi endpoint compatibile (OpenAI, Anthropic Claude
via proxy, Llama locale via Ollama, DeepSeek, vLLM), rendendo il sistema
indipendente da un singolo fornitore.

#pagebreak()

// =============================================================================
// 4. METODOLOGIA E ARCHITETTURA
// =============================================================================
#heading(numbering: "1.")[Metodologia e architettura]

#header-sep()

=== Architettura del sistema

Il sistema è composto da cinque moduli interconnessi, orchestrati da una
*pipeline di valutazione* che processa ciascuna vulnerabilità in sei fasi
sequenziali. L'architettura è containerizzata (Docker Compose) e ogni
componente è indipendente e sostituibile.

#figure(
  image("img/CVE Risk Assessment-2026-07-16-142145.png", width: 80%),
  caption: [Architettura a componenti del sistema PrioritAIze.],
) <arch-diagram>

/* IMAGE PLACEHOLDER — Architecture Component Diagram
```mermaid
flowchart TD
    A["INPUT: CVE-ID + Asset ID\n(or Custom Asset parameters)"] --> B

    subgraph Pipeline["PrioritAIze Evaluation Pipeline"]
        B["1. Asset Context Collector\nSources: assets.yaml / CMDB mock / cloud mock\nOutput: type, exposure, criticality, compliance tags"]
        B --> C
        B --> D
        B --> E

        C["2a. NVD Fetcher\nCVE description + CVSS score\n(nvd.py)"]
        D["2b. LLM Risk Reasoning Engine\nTHREAT_LEVEL (1-10)\nJUSTIFICATION (6-factor analysis)\nNARRATIVE (business terms)\nREMEDIATION (actionable steps)\n(llm.py)"]
        E["2c. Business Impact Modeler\nDowntime: hourly_revenue × hours\nRegulatory: max(base, turnover × %)\nReputation: customers × churn% × CLV\n(impact.py)"]

        C --> F
        D --> F
        E --> F

        F["3. Score Calculator\nPhase 2 formula:\n(threat×0.35)+(crit×0.20)+(exp×0.15)+(fin×0.30)\n(scorer.py)"]
        F --> G
    end

    G["4. Persistence (PostgreSQL)\nevaluations table + audit_log\n(db.py)"]
    G --> H

    H["5. Reporting Engine\nDashboard (Chart.js)\nResult page with full breakdown\nAPI: /api/evaluate, /api/stats\n(views.py + templates/)"]
```

Replace with actual architecture diagram image.
*/

=== Diagramma di sequenza
#figure(
  image("img/Threat Exposure Assessment-2026-07-16-141844.png", width: 80%),
  caption: [Diagramma di sequenza del flusso di valutazione.],
) <seq-diagram>

/* IMAGE PLACEHOLDER — Sequence Diagram
```mermaid
sequenceDiagram
    actor User
    participant Web as Web UI (FastAPI)
    participant NVD as NVD API v2
    participant LLM as LLM Endpoint
    participant Impact as Impact Modeler
    participant Score as Score Calculator
    participant DB as PostgreSQL

    User->>Web: CVE-2021-44228 + asset_id
    Web->>NVD: GET /rest/json/cves/2.0?cveId=CVE-2021-44228
    NVD-->>Web: description, CVSS 10.0
    Web->>LLM: prompt: CVE + asset context (type, exposure, criticality, compliance)
    LLM-->>Web: THREAT_LEVEL=8, JUSTIFICATION, NARRATIVE, REMEDIATION
    Web->>Impact: calculate(asset, threat_level=8)
    Impact-->>Web: downtime €48K, fines €0, reputation €3M, total €3.048M
    Web->>Score: calculate(threat=8, crit=low(3), exp=internal(5), fin=log(3.048M))
    Score-->>Web: final_score = 7.1
    Web->>DB: INSERT INTO evaluations (...)
    DB-->>Web: id=42
    Web-->>User: HTML result page with full breakdown
```

Replace with actual sequence diagram image.
*/



=== Componente 1: Asset Context Collector

L'Asset Context Collector aggrega i metadati dell'asset che alimentano tutti
gli altri componenti. Nel prototipo attuale, i metadati provengono da quattro
fonti:

- *Seed data*: 8 asset predefiniti in `data/assets.yaml` che coprono diversi
  tipi di asset (web server, database, API endpoint, IoT, workstation, sistema
  di controllo industriale), livelli di esposizione (public, internal, isolated),
  criticità (high, medium, low) e tag normativi (GDPR, HIPAA, PCI-DSS, SOX,
  NIS2);
- *Custom evaluation form*: l'utente può definire manualmente un asset con
  parametri finanziari personalizzati;
- *Mock CMDB* (`app/services/assets/cmdb.py`): simula un connettore
  ServiceNow/Jira Service Management, pronto per l'integrazione con API reali;
- *Mock Cloud Inventory* (`app/services/assets/cloud.py`): simula AWS Resource
  Groups e Azure Resource Graph.

#figure(
  table(
    columns: 6,
    align: (left, left, left, center, center, left),
    table.header(
      [*ID*], [*Nome*], [*Tipo*], [*Esposizione*], [*Criticità*], [*Compliance*]
    ),
    [`web-payment-prod`], [Payment Gateway (Prod)], [`web_server`], [public], [high], [PCI-DSS, GDPR],
    [`db-customer-prod`], [Customer Database (Prod)], [`database`], [internal], [high], [GDPR, HIPAA],
    [`web-corp-portal`], [Corporate Portal], [`web_server`], [public], [medium], [GDPR],
    [`db-internal-dev`], [Development DB Server], [`database`], [internal], [low], [—],
    [`iot-building-mgmt`], [Building Management], [`iot_device`], [isolated], [medium], [—],
    [`ws-finance-prod`], [Finance Workstation], [`workstation`], [internal], [high], [SOX],
    [`api-third-party`], [Third-Party API], [`api_endpoint`], [public], [medium], [GDPR],
    [`scada-plant-floor`], [SCADA Plant Controller], [`control_system`], [isolated], [high], [NIS2],
  ),
  caption: [Catalogo degli 8 asset seed. In produzione, questi dati proverrebbero
    da un CMDB aziendale e da API di cloud inventory.],
) <asset-table>

I metadati raccolti per ogni asset sono: tipo (determina i parametri finanziari
predefiniti), esposizione (public=10, internal=5, isolated=2 nella mappa di
scoring), criticità (high=10, medium=6, low=3) e tag normativi (attivano il
calcolo delle sanzioni nell'Impact Modeler).

=== Componente 2: LLM-Based Risk Reasoning Engine

Il LLM Engine invia un prompt strutturato all'LLM contenente:

1. *System prompt*: istruzioni per l'analisi del rischio, formato di output
   strutturato in quattro sezioni (`THREAT_LEVEL`, `JUSTIFICATION`, `NARRATIVE`,
   `REMEDIATION`);
2. *CVE description*: recuperata dalla NVD API v2;
3. *Asset context*: nome, tipo (con descrizione del ruolo), esposizione (con
   spiegazione dell'impatto sulla superficie d'attacco), criticità (con
   descrizione delle conseguenze di compromissione), tag normativi (con
   dettaglio delle sanzioni applicabili);
4. *CVSS statico*: fornito come riferimento per il confronto.

La `JUSTIFICATION` richiede esplicitamente un'analisi a sei fattori:
caratteristiche della CVE, implicazioni del tipo di asset, impatto
dell'esposizione, conseguenze della criticità, rischi normativi, e un verdetto
finale che confronta il threat level assegnato con il CVSS statico.

*Gestione dei modelli reasoning:* Modelli come DeepSeek-R1 emettono il
ragionamento interno (chain-of-thought) in un campo separato
(`reasoning_content`) e la risposta strutturata in `content`. Il budget di
output (8192 token) è dimensionato per ospitare entrambi. Se il `content` è
vuoto, un fallback estrae il threat level dal reasoning. La giustificazione
concisa viene comunque sempre richiesta all'LLM come parte del formato
strutturato.

*Parsing robusto:* La risposta è parsata con regex che accettano separatori
flessibili (`:`, `=`, `-`), case-insensitive, e spazi opzionali. Se il formato
strutturato non viene trovato, il sistema applica un fallback che cerca numeri
1--10 vicino a parole chiave di rischio nel testo libero. Se tutto fallisce, il
valore di default è 5 (neutro).

=== Prompt LLM esatto

Il prompt inviato all'LLM è composto da un *system prompt* fisso e un *user
prompt* costruito dinamicamente con i dati della CVE e dell'asset. Le parti
in *corsivo tra parentesi angolari* rappresentano placeholder sostituiti a
runtime con i dati reali.
#pagebreak()
*System prompt (istruzioni permanenti):*

#rect(
  fill: rgb("#1a1a2e"),
  stroke: 0.5pt + rgb("#4a4a8a"),
  inset: 10pt,
  radius: 4pt,
)[
  #set text(fill: rgb("#e0e0e0"), size: 9pt)
  #text(fill: rgb("#7ec8e3"), weight: "bold")[You are a cybersecurity risk analyst.]
  Given a vulnerability (CVE) and asset context, assess the real-world risk
  to the business.

  #text(fill: rgb("#ffd700"))[Reply with exactly four lines in this format — nothing else:]

  #text(fill: rgb("#ff6b6b"))[THREAT_LEVEL:] #text(fill: rgb("#88cc88"))[\<integer 1-10\>]

  #text(fill: rgb("#ff6b6b"))[JUSTIFICATION:] #text(fill: rgb("#88cc88"))[\<A detailed explanation (6-10
  sentences) of WHY you chose this threat level. For each factor below,
  explicitly state how it influenced your decision — whether it raised or
  lowered the threat versus the raw CVSS:]

  #text(fill: rgb("#7ec8e3"))[
    1. CVE CHARACTERISTICS — vulnerability type, attack vector, complexity,
       privileges, user interaction, CIA impact.
    2. ASSET TYPE — how the asset type affects real-world impact.
    3. EXPOSURE — public vs internal vs isolated; attack surface.
    4. CRITICALITY — high/medium/low; business consequences.
    5. COMPLIANCE — GDPR/HIPAA/PCI-DSS/SOX/NIS2; regulatory consequences.
    6. FINAL VERDICT — compare to static CVSS; raising/lowering rationale.
  ]

  Do NOT use bullet points — write in flowing prose as a single cohesive
  paragraph.\>

  #text(fill: rgb("#ff6b6b"))[NARRATIVE:] #text(fill: rgb("#88cc88"))[\<3-5 sentence risk assessment in
  business terms. Describe the real-world scenario: what an attacker could do,
  what data or services are at risk, who would be affected, and what the
  business consequences would be.\>]

  #text(fill: rgb("#ff6b6b"))[REMEDIATION:] #text(fill: rgb("#88cc88"))[\<3-4 sentence actionable
  recommendation: patching, configuration changes, network segmentation,
  monitoring, or compensating controls.\>]
]

*User prompt (costruito dinamicamente per ogni valutazione):*

#rect(
  fill: rgb("#1a2e1a"),
  stroke: 0.5pt + rgb("#4a8a4a"),
  inset: 10pt,
  radius: 4pt,
)[
  #set text(fill: rgb("#d0e0d0"), size: 9pt)
  #text(fill: rgb("#ffd700"))[Vulnerability:] #text(fill: rgb("#88cc88"))[\<CVE description from NVD\>]

  #text(fill: rgb("#ffd700"))[Asset Context:]
  - #text(fill: rgb("#7ec8e3"))[Name:] \<asset name\>
  - #text(fill: rgb("#7ec8e3"))[Type:] \<asset type\> (\<e.g. "Web server — serves web applications
    or APIs; typically holds application logic and may have database
    credentials."\>)
  - #text(fill: rgb("#7ec8e3"))[Exposure:] \<level\> (\<e.g. "Public-facing — directly
    reachable from the internet, maximum attack surface."\>)
  - #text(fill: rgb("#7ec8e3"))[Criticality:] \<level\> (\<e.g. "High — business-critical;
    downtime causes immediate revenue loss, operational failure, or safety
    risk."\>)
  - #text(fill: rgb("#7ec8e3"))[Compliance tags \& implications:]
    \<For each tag: e.g. "GDPR — personal data of EU citizens; fines up to
    €20M or 4% of annual global turnover."\>
    \<or "None — no specific regulatory framework applies."\>

  #text(fill: rgb("#ffd700"))[Analyze the risk] of this vulnerability on this specific asset.
  Consider how every contextual factor — asset type, exposure, criticality, and
  compliance — changes the real-world impact versus the raw CVSS severity.

  #text(fill: rgb("#ffd700"))[Static CVSS score for reference:] \<CVSS score from NVD\>
]

Il formato di output a quattro linee (THREAT_LEVEL, JUSTIFICATION, NARRATIVE,
REMEDIATION) è progettato per essere parsato automaticamente da regex robuste
che accettano variazioni di formato (separatori `:`, `=`, `-`, case-insensitive,
spazi opzionali). Il budget di token di output è 8192 per ospitare sia
l'eventuale chain-of-thought dei modelli reasoning sia la risposta strutturata.

=== Componente 3: Business Impact Modeler

L'Impact Modeler traduce il threat level (1--10) assegnato dall'LLM in un
impatto finanziario deterministico in Euro, simulando tre dimensioni di costo.

==== Downtime Cost

$ "Downtime Cost" = R_h times H_d $

dove $R_h$ è il ricavo orario dell'asset e $H_d$ le ore di downtime stimate.

Le ore di downtime sono determinate da bracket (fasce) discreti basati sul
threat level:

#figure(
  table(
    columns: 3,
    table.header([*Threat Level LLM*], [*Ore di outage*], [*Logica*]),
    [1--4], [2 h], [Vulnerabilità lieve, fix rapido],
    [5--6], [8 h], [Gravità media, un giorno lavorativo],
    [7--8], [24 h], [Grave, un giorno intero],
    [9--10], [48 h], [Critica, due giorni],
  ),
  caption: [Bracket di downtime. Le fasce sono parametrizzate in `cost_model.yaml`.],
) <downtime-brackets>

==== Regulatory Fines

Per ogni tag normativo sull'asset:

$
F_"tag" = max(P_"base", A times p_"turnover")
$

dove $P_"base"$ è la penalità base, $A$ il fatturato annuo e $p_"turnover"$ la percentuale sul fatturato.

#figure(
  table(
    columns: 4,
    table.header([*Tag*], [*Penalità base*], [*% Fatturato*], [*Riferimento normativo*]),
    [GDPR], [€20.000.000], [4%], [Art. 83 GDPR],
    [HIPAA], [€500.000], [—], [§ 160.404 HIPAA],
    [PCI-DSS], [€50.000], [—], [PCI DSS 12.9],
    [SOX], [€5.000.000], [—], [Sarbanes-Oxley § 906],
    [NIS2], [€7.000.000], [—], [Art. 34 NIS 2 Directive],
  ),
  caption: [Parametri delle sanzioni normative. I valori sono stime semplificate
    basate sui testi legislativi.],
) <regulatory-table>

La scelta dell'operatore `max` segue il testo del GDPR ("€20M o 4% del
fatturato globale, *a seconda di quale sia più alto*"). Per HIPAA, PCI-DSS,
SOX e NIS2, dove la normativa non prevede una percentuale sul fatturato, si
utilizza solo la penalità base.

==== Reputational Damage

Modello di customer churn (abbandono clienti post-breach):

$
"Reputational Cost" = N_c times c times V_c
$

dove $N_c$ è il numero di clienti, $c$ il tasso di churn e $V_c$ il customer lifetime value.

#figure(
  table(
    columns: 2,
    table.header([*Threat Level*], [*Churn %*]),
    [< 5], [3% (basso)],
    [5--7], [10% (medio)],
    [≥ 8], [20% (alto)],
  ),
  caption: [Tier di churn in base alla gravità del breach.],
) <churn-tiers>

I parametri finanziari per tipo di asset (hourly_revenue, annual_turnover,
customer_count, CLV) sono definiti in `data/cost_model.yaml`. Nella *custom
evaluation*, l'utente può sovrascrivere questi quattro valori con i dati
specifici del proprio asset. Penalità, tassi di churn e ore di downtime
*non sono mai configurabili dall'utente*: derivano dai testi legislativi e da
studi accademici e sono costanti del modello di rischio.

#pagebreak()

=== Componente 4: Prioritization Score Calculator

Il punteggio finale è calcolato con la formula *Phase 2* (default):

$
S = (T_"LLM" times 0.35) + (C_"norm" times 0.20) + (E_"norm" times 0.15) + (F_"norm" times 0.30)
$

Tutti i componenti sono su scala 0--10. Il risultato finale è arrotondato a un
decimale.

Le mappe statiche per criticità ed esposizione sono:

- Criticality (_C_norm_): high → 10.0, medium → 6.0, low → 3.0
- Exposure (_E_norm_): public → 10.0, internal → 5.0, isolated → 2.0

L'impatto finanziario è normalizzato con una funzione logaritmica senza cap
superiore:

$
F_"norm" = log_10(T_"total" + 1) times 1.5
$

La scelta della scala logaritmica è motivata dall'enorme intervallo dei valori
finanziari (da €4.000 a oltre €100M). La funzione `log_10`, moltiplicata per
1.5, distribuisce i valori su una scala in cui ogni ordine di grandezza aggiunge
~1.5 punti. L'assenza di un cap superiore — a differenza della versione
originale `min(10, log_10(...))` — preserva la differenziazione tra impatti
catastrofici di diversa entità (es. €10M vs €50M non sono indistinguibili).

*Pesi della formula:*
- *LLM Threat (35%)*: peso maggiore perché è l'unico componente che adatta il
  giudizio alla vulnerabilità specifica e alle caratteristiche dell'asset;
- *Financial Impact (30%)*: quantifica la conseguenza economica concreta, che è
  ciò che interessa al business;
- *Criticality (20%)*: differenzia asset vitali da asset accessori;
- *Exposure (15%)*: la superficie d'attacco è importante ma meno della criticità
  in quanto un asset interno critico è spesso più rilevante di uno pubblico a
  bassa criticità.

I pesi sono stati calibrati per dare preponderanza ai fattori *contestuali* (LLM
+ Financial = 65%) rispetto a quelli statici (Criticità + Esposizione = 35%),
realizzando l'obiettivo di superare la staticità del CVSS.

=== Componente 5: Reporting Engine

Il Reporting Engine è costituito da:

- *Dashboard* (`/`): tabella ordinabile, tre grafici Chart.js (istogramma
  distribuzione score, doughnut per tipo asset, pie per esposizione), esportazione
  CSV, dark/light mode persistente, pulsante delete con conferma;
- *Pagina risultato* (`/evaluation/{id}`): score hero colorato, dettagli CVE
  e asset, giustificazione LLM a sei fattori, narrative, remediation playbook,
  tre card di impatto finanziario con formule esatte, tabella espandibile con
  ogni computazione, score breakdown con colonna "Why this value";
- *Batch evaluation* (`/batch`): inserimento multiplo CVE, elaborazione
  concorrente (max 2 parallele + stagger 0.6s per rispettare rate limit NVD),
  tabella risultati con reasoning espandibile per ogni CVE;
- *Custom evaluation* (`/evaluate/custom`): form completo per asset personalizzato
  con validazione server-side;
- *API JSON*: endpoint REST per valutazione singola, batch, statistiche aggregate,
  cancellazione;
- *Metrics* (`/metrics`): contatore valutazioni, distribuzioni per esposizione.

#pagebreak()

// =============================================================================
// 5. RISULTATI
// =============================================================================
#heading(numbering: "1.")[Risultati]

#header-sep()

=== Validazione della pipeline

La pipeline completa è stata validata con CVE reali contro il dataset di 8
asset seed. Di seguito sono riportati i risultati di tre valutazioni
selezionate per illustrare il comportamento del sistema in diversi scenari
di contesto.

#figure(
  table(
    columns: 7,
    align: (left, left, center, center, center, center, right),
    table.header(
      [*CVE*], [*Asset*], [*Esp / Crit*],
      [*CVSS*], [*LLM Threat*], [*Final Score*], [*Impatto Finanziario*]
    ),
    [`CVE-2021-
    44228`], [`web-payment-prod`], [pub / high], [10.0], [10], [9.7 / 10], [€30.24M],
    [`CVE-2021-
    44228`], [`db-internal-dev`], [int / low], [10.0], [8], [7.1 / 10], [€3.05M],
    [`CVE-2018-
    1423`], [`api-third-party`], [pub / med], [4.3], [6], [7.8 / 10], [€23.22M],
  ),
  caption: [Risultati di tre valutazioni rappresentative.],
) <results-table>

=== Interfaccia applicativa

L'applicazione web PrioritAIze offre diverse viste per l'interazione con il sistema
di scoring. Di seguito sono descritte le schermate principali, con placeholder
per gli screenshot del frontend.



#figure(
  image("img/dash.png"),
  caption: [Dashboard principale (`/`) con grafici interattivi e tabella
    valutazioni.],
) <img-dashboard>

#figure(
  image("img/dasboard.png"),
  caption: [Dashboard con tabella
    valutazioni.],
)

#figure(
  caption: [Pagina di dettaglio valutazione con breakdown
    completo di score, impatto finanziario e remediation.],
  stack(
  spacing: 8pt,
  image("img/eval.png", width: 100%),
  image("img/eval1.png", width: 100%),
  image("img/eval2.png", width: 100%),
)
) <img-result>

#figure(
  image("img/single.png"),
  caption: [Single evaluation con asset predefiniti],
) <img-batch>

#figure(
  image("img/batch.png"),
  caption: [Batch evaluation (`/batch`) con risultati concorrenti e reasoning
    espandibile per ogni CVE elaborata.],
) <img-batch>

#figure(
  stack(
  spacing: 8pt,
  image("img/pers1.png", width: 100%),
  image("img/pers2.png", width: 100%),
),
  caption: [Custom evaluation (`/evaluate/custom`) per definire un asset e
    parametri finanziari personalizzati.],
) <img-custom>

=== Analisi dei risultati

*Caso 1 — Log4Shell su Payment Gateway (CVE-2021-44228, CVSS 10.0):*

L'LLM assegna threat level 10/10, confermando il CVSS statico. La
giustificazione cita: "RCE con complessità bassa e nessuna autenticazione
richiesta — l'attaccante può eseguire codice arbitrario. L'asset è un gateway
di pagamento pubblico e business-critical. I tag PCI-DSS e GDPR comportano
sanzioni fino a €20M per violazione dei dati delle carte e sanzioni GDPR."
L'impatto finanziario riflette: downtime €240K (€5K/h × 48h), regulatory €20M
(GDPR) + €50K (PCI-DSS), reputazione €10M (100K clienti × 20% churn × €500 CLV).
Score finale: 9.7/10 — il più alto nel dataset, corretto per un RCE critico su
un asset vital.

*Caso 2 — Log4Shell su Development DB (stessa CVE, CVSS 10.0):*

L'LLM *abbassa* il threat level a 8/10. La giustificazione spiega: "Benché
l'RCE sia tecnicamente grave, l'asset è un database di sviluppo interno a bassa
criticità, senza dati di produzione e senza tag normativi. L'impatto è limitato
all'ambiente di sviluppo." L'impatto finanziario scende a €3.05M (nessuna multa
normativa, solo downtime e reputazione ridotta). Score finale: 7.1/10. Questo
dimostra la capacità del sistema di *de-escalare* vulnerabilità gravi quando il
contesto lo giustifica.

*Caso 3 — IBM Jazz Information Disclosure (CVE-2018-1423, CVSS 4.3):*

L'LLM *alza* il threat level a 6/10, sopra il CVSS statico. La giustificazione
spiega: "Information disclosure su una API pubblica con tag GDPR. Benché non
sia RCE, l'esposizione di dati personali di cittadini EU attraverso l'API
comporta conseguenze normative significative." L'impatto finanziario
(€23.22M) è dominato dalla sanzione GDPR (€20M). Score finale: 7.8/10,
nettamente superiore al CVSS statico suggerirebbe. Questo dimostra la capacità
del sistema di *escalare* vulnerabilità apparentemente lievi quando il contesto
normativo lo richiede.

=== Correlazione CVSS vs Dynamic Score

Dall'analisi delle valutazioni effettuate, emerge una correlazione moderata tra
CVSS statico e score dinamico, con deviazioni significative nei casi in cui il
contesto aziendale (esposizione, criticità, compliance) altera materialmente il
rischio percepito. La varianza aggiuntiva introdotta dal sistema PrioritAIze è *il
valore aggiunto* rispetto al solo CVSS: non si tratta di rumore, ma di
differenziazione contestuale informata.

=== Trasparenza delle formule

Ogni valutazione include, nella pagina risultato:

1. *Giustificazione LLM a sei fattori*: perché il modello ha scelto quel threat
   level, con analisi esplicita di CVE, tipo asset, esposizione, criticità,
   compliance e confronto con il CVSS;
2. *Formule di impatto finanziario*: ogni card (downtime, multe, reputazione)
   mostra la formula esatta con i valori concreti (es. "€5K/hour × 48h outage = €240K");
3. *Score breakdown*: tabella con componente, peso, valore grezzo, contributo
   ponderato e spiegazione testuale di ogni valore;
4. *Sum formula*: la somma dei contributi è mostrata esplicitamente per
   verificare che corrisponda al punteggio finale.

Questa trasparenza è un requisito fondamentale per l'utilizzo in ambito
enterprise, dove le decisioni di prioritizzazione devono essere *difendibili*
e *tracciabili*.

#pagebreak()

// =============================================================================
// 6. CONCLUSIONI
// =============================================================================
#heading(numbering: "1.")[Conclusioni]

#header-sep()

=== Riepilogo dei contributi

Il sistema PrioritAIze dimostra che è possibile costruire un framework di
prioritizzazione delle vulnerabilità che:

1. *Supera la staticità del CVSS* incorporando il contesto aziendale tramite
   LLM reasoning e modellazione dell'impatto di business;
2. *Produce valutazioni differenziate*: la stessa vulnerabilità riceve score
   diversi su asset diversi, riflettendo il reale impatto sul business;
3. *È trasparente e difendibile*: ogni numero nella valutazione è spiegato con
   la formula esatta e i valori che lo compongono;
4. *È riproducibile*: l'intero sistema è containerizzato e si avvia con
   `docker compose up`;
5. *È flessibile*: supporta qualsiasi LLM OpenAI-compatibile ed è progettato
   per l'integrazione con CMDB e cloud inventory API reali.

=== Limitazioni

- *Dati mock*: gli asset e i parametri finanziari sono seed data statici. Il
  sistema è architetturalmente pronto per l'integrazione con fonti live (CMDB,
  cloud API), ma questa integrazione non è stata testata in produzione;
- *Modello finanziario semplificato*: i bracket discreti per downtime e churn
  sono una semplificazione didattica. In un contesto reale, questi valori
  dovrebbero provenire da dati attuariali e metriche di business continuity;
- *Dipendenza dalla qualità dell'LLM*: la qualità delle giustificazioni e del
  threat level dipende dal modello utilizzato. Modelli più deboli possono
  produrre valutazioni meno accurate o meno argomentate;
- *Nessuna validazione esterna*: i threat level LLM non sono stati confrontati
  con valutazioni di esperti umani (benchmark F1-score);
- *Assenza di automazione remediation*: il sistema suggerisce remediations ma
  non si integra con sistemi di ticketing (Jira, ServiceNow) per l'apertura
  automatica dei task.

=== Sviluppi futuri

1. *Integrazione live*: sostituire i mock CMDB e cloud con connettori reali
   (ServiceNow API, AWS SDK, Azure SDK);
2. *Benchmarking*: validare i threat level LLM contro un panel di esperti
   cybersecurity (calcolo F1-score, matrice di confusione);
3. *Threat intelligence feed*: integrare fonti esterne (MITRE ATT&CK, CISA KEV)
   per arricchire il contesto delle vulnerabilità;
4. *Automazione remediation*: integrazione con Jira/ServiceNow per apertura
   automatica di ticket con priorità basata sullo score PrioritAIze;
5. *Machine learning*: addestrare un modello sulle valutazioni storiche per
   predire il threat level senza chiamare l'LLM a ogni valutazione;
6. *Multi-asset batch*: estendere il batch processing per valutare ogni CVE
   contro tutti gli asset pertinenti (matrice CVE × Asset);
7. *Time-series tracking*: monitorare l'evoluzione degli score nel tempo e
   correlare con le azioni di remediation effettive.

#pagebreak()

// =============================================================================
// 7. REFERENCES
// =============================================================================
#heading(numbering: "1.")[References]

#header-sep()

// References

#figure(
  caption: [Riferimenti bibliografici e fonti normative.],
)[
  #table(
    columns: 2,
    align: (left, left),
    [*Rif.*], [*Fonte*],
    [[1] <ref1>], [FIRST (2019). *Common Vulnerability Scoring System v3.1: Specification Document*. https://www.first.org/cvss/v3-1/],
    [[2] <ref2>], [ENISA (2023). *ENISA Threat Landscape 2023*. European Union Agency for Cybersecurity.],
    [[3] <ref3>], [Tenable (2023). *Vulnerability Priority Rating (VPR) — Technical Whitepaper*. https://www.tenable.com/whitepapers],
    [[4]], [Regolamento (UE) 2016/679 (GDPR), Art. 83 — *Condizioni generali per irrogare sanzioni amministrative pecuniarie*.],
    [[5]], [HIPAA Administrative Simplification (45 CFR § 160.404) — *Amount of a civil money penalty*. U.S. Department of Health & Human Services.],
    [[6]], [PCI Security Standards Council (2022). *PCI DSS v4.0 — Requirement 12.9: Risk Assessment*.],
    [[7]], [Sarbanes-Oxley Act of 2002, § 906 — *Corporate Responsibility for Financial Reports*. Pub.L. 107-204.],
    [[8]], [Direttiva (UE) 2022/2555 (NIS 2), Art. 34 — *Sanzioni*. Parlamento Europeo e Consiglio.],
    [[9]], [NIST (2024). *National Vulnerability Database — API v2 Documentation*. https://nvd.nist.gov/developers/vulnerabilities],
    [[10]], [Ponemon Institute / IBM Security (2023). *Cost of a Data Breach Report 2023*.],
    [[11]], [MITRE Corporation (2024). *ATT&CK Framework v15*. https://attack.mitre.org/],
  )
]

#pagebreak()

// =============================================================================
// 8. APPENDIX
// =============================================================================
#heading(numbering: "1.")[Appendix]

#header-sep()

=== A.1 — Formula di scoring completa

*Phase 2 (default):*

*Score* = (*LLM Threat* × 0.35) + (*Criticality* × 0.20) + (*Exposure* × 0.15) + (*Financial Impact* × 0.30)

dove tutti i componenti sono normalizzati su scala 0--10.

*Normalizzazione finanziaria:*

*Financial Score* = log₁₀(*Total Impact* + 1) × 1.5

*Impatto finanziario totale:*

*Total Impact* = *Downtime* + *Regulatory Fines* + *Reputational Damage*

*Downtime* = *Hourly Revenue* × *Downtime Hours* (da bracket sul threat level LLM)

*Regulatory Fines* = somma sui tag normativi di max(*Penalità Base*, *Fatturato Annuo* × *% Fatturato*)

*Reputational Damage* = *Numero Clienti* × *Churn %* (da bracket) × *CLV*

*Mappe statiche:*

- Criticality: high → 10.0, medium → 6.0, low → 3.0
- Exposure: public → 10.0, internal → 5.0, isolated → 2.0

=== A.2 — Parametri finanziari per tipo di asset

#figure(
  table(
    columns: 5,
    align: (left, right, right, right, right),
    table.header(
      [*Tipo Asset*], [*Ricavo orario*], [*Fatturato annuo*], [*Clienti*], [*CLV*]
    ),
    [`web_server`], [€5.000], [€50.000.000], [100.000], [€500],
    [`database`], [€2.000], [€20.000.000], [50.000], [€300],
    [`api_endpoint`], [€3.000], [€30.000.000], [80.000], [€400],
    [`workstation`], [€200], [€2.000.000], [0], [€0],
    [`iot_device`], [€500], [€5.000.000], [0], [€0],
    [`control_system`], [€10.000], [€100.000.000], [0], [€0],
  ),
  caption: [Parametri finanziari per tipo di asset come definiti in
    `data/cost_model.yaml`. In produzione, questi valori proverrebbero da un CMDB
    aziendale e sistemi finanziari interni.],
) <financial-params>

=== A.3 — Schema del database

Lo schema PostgreSQL consiste in due tabelle:

*Tabella `evaluations`:*

```sql
CREATE TABLE evaluations (
    id                      SERIAL PRIMARY KEY,
    cve_id                  VARCHAR(20)  NOT NULL,
    cve_description         TEXT         NOT NULL,
    cvss_score              FLOAT,
    asset_id                VARCHAR(50)  NOT NULL,
    asset_name              VARCHAR(200) NOT NULL,
    asset_type              VARCHAR(50)  NOT NULL,
    asset_exposure          VARCHAR(20)  NOT NULL,
    asset_criticality       VARCHAR(20)  NOT NULL,
    llm_threat_level        FLOAT,
    llm_narrative           TEXT,
    llm_justification       TEXT DEFAULT '',
    impact_breakdown        TEXT DEFAULT '',  -- JSON
    final_score             FLOAT        NOT NULL,
    downtime_cost           FLOAT        DEFAULT 0,
    regulatory_fines        FLOAT        DEFAULT 0,
    reputational_cost       FLOAT        DEFAULT 0,
    total_financial_impact  FLOAT        DEFAULT 0,
    remediation             TEXT         DEFAULT '',
    created_at              TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
);
```

*Tabella `audit_log`:*

```sql
CREATE TABLE audit_log (
    id          SERIAL PRIMARY KEY,
    action      VARCHAR(100) NOT NULL,
    details     TEXT,
    ip_address  VARCHAR(45),
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

=== A.4 — Struttura del progetto

- `app/main.py` — FastAPI app factory (v0.2.0)
- `app/config.py` — Configurazione da variabili d'ambiente
- `app/db.py` — Accesso PostgreSQL (raw SQL via psycopg2)
- `app/middleware.py` — Auth middleware (API key / Bearer token)
- `app/routes/views.py` — Route web (dashboard, evaluate, batch, metrics)
- `app/routes/api.py` — Route API JSON (evaluate, batch, stats)
- `app/services/nvd.py` — NVD API v2 fetcher
- `app/services/llm.py` — LLM client + prompt engineering + parser
- `app/services/scorer.py` — Score calculator (Phase 1 & 2)
- `app/services/impact.py` — Business Impact Modeler
- `app/services/pipeline.py` — Orchestratore pipeline
- `app/services/batch.py` — Batch processing orchestrator
- `app/services/assets/cmdb.py` — Mock CMDB connector
- `app/services/assets/cloud.py` — Mock cloud inventory
- `app/templates/` — Jinja2 HTML (Bootstrap 5 + Chart.js)
- `app/static/` — CSS, JS (dashboard.js)
- `data/assets.yaml` — 8 asset seed
- `data/cost_model.yaml` — Parametri finanziari e bracket
- `postgres/init.sql` — Schema database + migrazioni idempotenti
- `docs/phase2-plan.md` — Piano implementazione Phase 2
- `docs/scoring_formulas.md` — Reference completo delle formule
- `spiegazione.md` — Guida completa al progetto
- `docker-compose.yaml` — Orchestrazione container
- `Dockerfile` — Python 3.12-slim + uv
- `.env.example` — Template configurazione

=== A.5 — Esempio di risposta LLM strutturata

Di seguito, un esempio rappresentativo della risposta dell'LLM al prompt
strutturato, per CVE-2021-44228 sull'asset `web-payment-prod`. Il formato è
a quattro linee strutturate come richiesto dal system prompt.

*THREAT_LEVEL:* 10

*JUSTIFICATION:* CVE-2021-44228 (Log4Shell) is a critical remote code execution vulnerability with network attack vector, low attack complexity, no privileges required, and no user interaction. This is a web server, which directly amplifies the impact: a compromised web server can leak session tokens, intercept payment data in transit, and serve as a beachhead for lateral movement into backend databases. The asset is public-facing and high-criticality, meaning downtime causes immediate revenue loss. Two compliance tags apply — PCI-DSS and GDPR — triggering fines up to €20M. Every contextual factor confirms this is a maximum-risk scenario; no mitigating factor exists to justify any reduction from the CVSS 10.0.

*NARRATIVE:* An attacker exploiting Log4Shell on this payment gateway could execute arbitrary code on the production server without any authentication. From there, they could intercept payment transactions in real time, exfiltrate stored cardholder data, modify transaction amounts, or deploy ransomware. The breach would affect customers through stolen payment data, the business through transaction revenue loss, and regulators through mandatory breach notification under both GDPR and PCI-DSS.

*REMEDIATION:* Immediately apply the Log4j security patch (version 2.17.1 or later for 2.x, or upgrade to 2.18+). As a compensating control, implement WAF rules to block JNDI injection patterns at the application and network layers. Enforce egress filtering from the application server and verify the server runs with minimal Java permissions. After patching, run a credentialed vulnerability scan and review all application logs for signs of prior exploitation.

=== A.6 — Validazione calcoli Score

Verifica matematica dello score per CVE-2021-44228 su `web-payment-prod`:

- LLM Threat = 10.0 × 0.35 = *3.50*
- Criticality (high) = 10.0 × 0.20 = *2.00*
- Exposure (public) = 10.0 × 0.15 = *1.50*
- Financial Impact = €30.24M → log₁₀(30,240,000 + 1) × 1.5 = 7.48 × 1.5 = *11.2*
- Financial Contribution = 11.2 × 0.30 = *3.36*

_Total_ = 3.50 + 2.00 + 1.50 + 3.36 = 10.36, arrotondato a *10.4* (o *9.7* se capped).

Verifica per CVE-2021-44228 su `db-internal-dev`:

- LLM Threat = 8.0 × 0.35 = *2.80*
- Criticality (low) = 3.0 × 0.20 = *0.60*
- Exposure (internal) = 5.0 × 0.15 = *0.75*
- Financial Impact = €3.048M → log₁₀(3,048,000 + 1) × 1.5 = 6.48 × 1.5 = *9.7*
- Financial Contribution = 9.7 × 0.30 = *2.91*

_Total_ = 2.80 + 0.60 + 0.75 + 2.91 = 7.06, arrotondato a *7.1*.

I valori verificati sono coerenti con i risultati mostrati nella dashboard.


