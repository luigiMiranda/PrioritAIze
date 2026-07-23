# Analisi LLM Threat Level vs CVSS Score

**Dataset:** 4 valutazioni

---
## 1. Metriche di Accuratezza (LLM Threat vs CVSS)

| Metrica | Valore | Interpretazione |
|---------|-------|-----------------|
| **MAE** (Mean Absolute Error) | **1.10** | In media, il LLM si discosta di 1.10 punti dal CVSS |
| **RMSE** (Root Mean Squared Error) | **1.36** | Penalizza delta grandi (sqrt media dei quadrati) |
| **Pearson r** | **0.911** | forte correlazione lineare — LLM e CVSS tendono a concordare sull'ordine di grandezza |
| **Spearman rho** | **0.800** | forte concordanza ordinale — il LLM mantiene all'incirca l'ordine di severità del CVSS |

---
## 2. Analisi dei Delta (LLM − CVSS)

**Delta medio complessivo:** 0.10

| Direzione | Count | % |
|----------|-------|---|
| **Rialzato** (LLM > CVSS di >=0.5) | 2 | 50% |
| **Abbassato** (LLM < CVSS di >=0.5) | 1 | 25% |
| **Allineato** (|delta| < 0.5) | 1 | 25% |

### 2.1 Delta per Exposure

| Exposure | Count | Delta Medio | Min | Max | Alzati | Abbassati |
|----------|-------|------------|-----|-----|--------|-----------|
| public | 3 | +0.80 | +0.0 | +1.7 | 2 | 0 |
| internal | 1 | -2.00 | -2.0 | -2.0 | 0 | 1 |

### 2.2 Delta per Criticality

| Criticality | Count | Delta Medio | Min | Max | Alzati | Abbassati |
|------------|-------|------------|-----|-----|--------|-----------|
| high | 1 | +0.00 | +0.0 | +0.0 | 0 | 0 |
| medium | 2 | +1.20 | +0.7 | +1.7 | 2 | 0 |
| low | 1 | -2.00 | -2.0 | -2.0 | 0 | 1 |

### 2.3 Delta per Asset Type

| Asset Type | Count | Delta Medio | Min | Max |
|------------|-------|------------|-----|-----|
| api_endpoint | 2 | +1.20 | +0.7 | +1.7 |
| database | 1 | -2.00 | -2.0 | -2.0 |
| web_server | 1 | +0.00 | +0.0 | +0.0 |

### 2.4 Delta per Compliance Tag

| Compliance | Count | Delta Medio | Min | Max |
|------------|-------|------------|-----|-----|
| GDPR | 3 | +0.80 | +0.0 | +1.7 |
| PCI-DSS | 1 | +0.00 | +0.0 | +0.0 |

---
## 3. Dettaglio Valutazioni

| CVE | Asset | CVSS | LLM Threat | Delta | Exposure | Criticality | Spiegazione Delta |
|-----|-------|------|------------|-------|----------|-------------|-------------------|
| CVE-2021-44228 | web-payment-prod | 10.0 | 10.0 | +0.0 | public | high | Critical RCE in widely used logging library; public-facing payment gateway with … |
| CVE-2021-44228 | db-internal-dev | 10.0 | 8.0 | -2.0 | internal | low | RCE is severe but asset is internal dev DB with low criticality and no complianc… |
| CVE-2026-45264 | api-third-party | 4.3 | 5.0 | +0.7 | public | medium | SSRF on public-facing API with GDPR data; limited to server-side requests, not f… |
| CVE-2018-1423 | api-third-party | 4.3 | 6.0 | +1.7 | public | medium | Info disclosure on public API with GDPR data is data-breach vector; raised above… |

---
## 5. Interpretazione

### Cosa significa il MAE

Un MAE di **1.10** su scala 0-10 significa che il LLM si discosta in media di 1.10 punti dal CVSS. Questo è **atteso e desiderabile**: il sistema è progettato per contestualizzare, non per replicare il CVSS.

### Pattern osservati

- **Asset pubblici** (delta medio +0.80): il LLAM tende ad alzare il threat perché l'esposizione pubblica aumenta l'attack surface e la probabilità di sfruttamento. **Pattern corretto e atteso.**
- **Asset interni** (delta medio -2.00): il LLM tende ad abbassare il threat perché l'accesso è limitato alla rete interna. **Pattern corretto e atteso.**
- **Asset ad alta criticità** (delta medio +0.00): il LLM mantiene o alza il threat per asset critici, riflettendo il maggiore impatto aziendale in caso di compromissione. **Pattern corretto.**
- **Asset a bassa criticità** (delta medio -2.00): il LLM riduce il threat quando l'asset ha impatto aziendale limitato. **Pattern corretto.**

### Conclusione

Il sistema mostra una correlazione forte con il CVSS (r = 0.911) ma si discosta in modo **sistematico e giustificato** in base al contesto dell'asset. I delta positivi per asset pubblici/critici e negativi per asset interni/bassa criticità dimostrano che il LLM sta effettivamente contestualizzando il rischio, non limitandosi a replicare il CVSS.

*Nota: i risultati sono basati su un campione limitato di valutazioni. Un campione più ampio (30+) aumenterebbe la significatività statistica.*
