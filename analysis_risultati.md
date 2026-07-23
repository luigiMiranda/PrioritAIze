# Analisi LLM Threat Level vs CVSS Score

**Dataset:** 56 valutazioni (7 CVE x 8 asset)

**Periodo:** Valutazioni simulate dal modello di contestualizzazione

---
## 1. Riepilogo Metriche

| Metrica | Valore | Interpretazione |
|---------|-------|-----------------|
| **MAE** | **1.08** | Scostamento medio assoluto LLM vs CVSS (su 0-10) |
| **RMSE** | **1.37** | Penalizza delta grandi (sqrt media quadrati) |
| **Pearson r** | **0.844** | Correlazione lineare forte — LLM allineato col CVSS ma non identico |
| **Spearman rho** | **0.831** | Concordanza ordinale — l'ordine di severita' e' preservato |
| **Delta medio** | **-0.53** | Media delle differenze (LLM - CVSS) |

### Distribuzione Final Score

| 0-2 | 2-4 | 4-6 | 6-8 | 8-10 |
|---|---|---|---|---|
| 0 | 3 | 11 | 23 | 19 |
| 0% | 5% | 20% | 41% | 34% |

**Score medio:** 7.14

---
## 2. Analisi dei Delta (LLM - CVSS)

**Delta medio complessivo:** -0.53

| Direzione | Count | % |
|----------|-------|---|
| **Rialzato** (delta >= +0.5) | 11 | 20% |
| **Abbassato** (delta <= -0.5) | 28 | 50% |
| **Allineato** (|delta| < 0.5) | 17 | 30% |

### 2.1 Delta per Exposure

| Exposure | Count | Delta Medio | Min | Max | Alzati | Abbassati |
|----------|-------|------------|-----|-----|--------|-----------|
| public | 21 | +0.24 | -1.0 | +2.6 | 6 | 4 |
| internal | 21 | -0.76 | -3.1 | +1.8 | 4 | 13 |
| isolated | 14 | -1.36 | -2.8 | +0.8 | 1 | 11 |

### 2.2 Delta per Criticality

| Criticality | Count | Delta Medio | Min | Max | Alzati | Abbassati |
|------------|-------|------------|-----|-----|--------|-----------|
| high | 28 | -0.13 | -2.0 | +2.6 | 7 | 12 |
| medium | 21 | -0.56 | -2.8 | +1.8 | 4 | 10 |
| low | 7 | -2.06 | -3.1 | -0.3 | 0 | 6 |

### 2.3 Delta per Asset Type

| Asset Type | Count | Delta Medio | Min | Max |
|------------|-------|------------|-----|-----|
| web_server | 14 | +0.34 | -1.0 | +2.6 |
| database | 14 | -1.01 | -3.1 | +1.8 |
| api_endpoint | 7 | +0.04 | -1.0 | +1.8 |
| iot_device | 7 | -1.76 | -2.8 | +0.0 |
| workstation | 7 | -0.26 | -1.3 | +1.5 |
| control_system | 7 | -0.96 | -2.0 | +0.8 |

### 2.4 Delta per Compliance Tag

| Compliance | Count | Delta Medio | Min | Max |
|------------|-------|------------|-----|-----|
| GDPR | 28 | +0.19 | -1.0 | +2.6 |
| HIPAA | 7 | +0.04 | -1.0 | +1.8 |
| NIS2 | 7 | -0.96 | -2.0 | +0.8 |
| PCI-DSS | 7 | +0.64 | -0.2 | +2.6 |
| SOX | 7 | -0.26 | -1.3 | +1.5 |

### 2.5 Delta per Tipo di CVE

| Tipo CVE | Count | Delta Medio | Min | Max |
|----------|-------|------------|-----|-----|
| Container Escape | 8 | -1.05 | -2.6 | +0.3 |
| DoS | 8 | -1.55 | -3.1 | -0.2 |
| Info Disclosure | 8 | +1.25 | -0.3 | +2.6 |
| RCE | 24 | -0.88 | -2.5 | +0.2 |
| SSRF | 8 | +0.25 | -1.3 | +1.6 |

---
## 3. Dettaglio Valutazioni

| CVE | Asset | CVSS | LLM | D | Exposure | Crit. | Giustificazione |
|-----|-------|------|-----|----|----------|-------|----------------|
| CVE-2021-44228 | web-payment-prod | 10.0 | 10.0 | +0.0 | public | high | Log4Shell - RCE in Apache Log4j on Payment Gateway (Prod). (public, high criticality). com... |
| CVE-2021-44228 | db-customer-prod | 10.0 | 9.8 | -0.2 | internal | high | Log4Shell - RCE in Apache Log4j on Customer Database (Prod). (internal, high criticality).... |
| CVE-2021-44228 | web-corp-portal | 10.0 | 9.8 | -0.2 | public | medium | Log4Shell - RCE in Apache Log4j on Corporate Portal. (public, medium criticality). complia... |
| CVE-2021-44228 | db-internal-dev | 10.0 | 7.7 | -2.3 | internal | low | Log4Shell - RCE in Apache Log4j on Dev Database Server. (internal, low criticality). threa... |
| CVE-2021-44228 | iot-building-mgmt | 10.0 | 8.0 | -2.0 | isolated | medium | Log4Shell - RCE in Apache Log4j on Building Management. (isolated, medium criticality). th... |
| CVE-2021-44228 | ws-finance-prod | 10.0 | 9.5 | -0.5 | internal | high | Log4Shell - RCE in Apache Log4j on Finance Workstation. (internal, high criticality). comp... |
| CVE-2021-44228 | api-third-party | 10.0 | 9.8 | -0.2 | public | medium | Log4Shell - RCE in Apache Log4j on Third-Party Integration API. (public, medium criticalit... |
| CVE-2021-44228 | scada-plant-floor | 10.0 | 8.8 | -1.2 | isolated | high | Log4Shell - RCE in Apache Log4j on SCADA Plant Controller. (isolated, high criticality). c... |
| CVE-2022-22965 | web-payment-prod | 9.8 | 10.0 | +0.2 | public | high | Spring4Shell - RCE in Spring Framework on Payment Gateway (Prod). (public, high criticalit... |
| CVE-2022-22965 | db-customer-prod | 9.8 | 9.4 | -0.4 | internal | high | Spring4Shell - RCE in Spring Framework on Customer Database (Prod). (internal, high critic... |
| CVE-2022-22965 | web-corp-portal | 9.8 | 9.4 | -0.4 | public | medium | Spring4Shell - RCE in Spring Framework on Corporate Portal. (public, medium criticality). ... |
| CVE-2022-22965 | db-internal-dev | 9.8 | 7.3 | -2.5 | internal | low | Spring4Shell - RCE in Spring Framework on Dev Database Server. (internal, low criticality)... |
| CVE-2022-22965 | iot-building-mgmt | 9.8 | 7.6 | -2.2 | isolated | medium | Spring4Shell - RCE in Spring Framework on Building Management. (isolated, medium criticali... |
| CVE-2022-22965 | ws-finance-prod | 9.8 | 9.1 | -0.7 | internal | high | Spring4Shell - RCE in Spring Framework on Finance Workstation. (internal, high criticality... |
| CVE-2022-22965 | api-third-party | 9.8 | 9.4 | -0.4 | public | medium | Spring4Shell - RCE in Spring Framework on Third-Party Integration API. (public, medium cri... |
| CVE-2022-22965 | scada-plant-floor | 9.8 | 8.4 | -1.4 | isolated | high | Spring4Shell - RCE in Spring Framework on SCADA Plant Controller. (isolated, high critical... |
| CVE-2023-46604 | web-payment-prod | 10.0 | 10.0 | +0.0 | public | high | Apache ActiveMQ - RCE via openwire on Payment Gateway (Prod). (public, high criticality). ... |
| CVE-2023-46604 | db-customer-prod | 10.0 | 9.8 | -0.2 | internal | high | Apache ActiveMQ - RCE via openwire on Customer Database (Prod). (internal, high criticalit... |
| CVE-2023-46604 | web-corp-portal | 10.0 | 9.8 | -0.2 | public | medium | Apache ActiveMQ - RCE via openwire on Corporate Portal. (public, medium criticality). comp... |
| CVE-2023-46604 | db-internal-dev | 10.0 | 7.7 | -2.3 | internal | low | Apache ActiveMQ - RCE via openwire on Dev Database Server. (internal, low criticality). th... |
| CVE-2023-46604 | iot-building-mgmt | 10.0 | 8.0 | -2.0 | isolated | medium | Apache ActiveMQ - RCE via openwire on Building Management. (isolated, medium criticality).... |
| CVE-2023-46604 | ws-finance-prod | 10.0 | 9.5 | -0.5 | internal | high | Apache ActiveMQ - RCE via openwire on Finance Workstation. (internal, high criticality). c... |
| CVE-2023-46604 | api-third-party | 10.0 | 9.8 | -0.2 | public | medium | Apache ActiveMQ - RCE via openwire on Third-Party Integration API. (public, medium critica... |
| CVE-2023-46604 | scada-plant-floor | 10.0 | 8.8 | -1.2 | isolated | high | Apache ActiveMQ - RCE via openwire on SCADA Plant Controller. (isolated, high criticality)... |
| CVE-2023-44487 | web-payment-prod | 7.5 | 7.3 | -0.2 | public | high | HTTP/2 Rapid Reset - DDoS on Payment Gateway (Prod). (public, high criticality). complianc... |
| CVE-2023-44487 | db-customer-prod | 7.5 | 6.5 | -1.0 | internal | high | HTTP/2 Rapid Reset - DDoS on Customer Database (Prod). (internal, high criticality). compl... |
| CVE-2023-44487 | web-corp-portal | 7.5 | 6.5 | -1.0 | public | medium | HTTP/2 Rapid Reset - DDoS on Corporate Portal. (public, medium criticality). compliance: G... |
| CVE-2023-44487 | db-internal-dev | 7.5 | 4.4 | -3.1 | internal | low | HTTP/2 Rapid Reset - DDoS on Dev Database Server. (internal, low criticality). threat 4.4/... |
| CVE-2023-44487 | iot-building-mgmt | 7.5 | 4.7 | -2.8 | isolated | medium | HTTP/2 Rapid Reset - DDoS on Building Management. (isolated, medium criticality). threat 4... |
| CVE-2023-44487 | ws-finance-prod | 7.5 | 6.2 | -1.3 | internal | high | HTTP/2 Rapid Reset - DDoS on Finance Workstation. (internal, high criticality). compliance... |
| CVE-2023-44487 | api-third-party | 7.5 | 6.5 | -1.0 | public | medium | HTTP/2 Rapid Reset - DDoS on Third-Party Integration API. (public, medium criticality). co... |
| CVE-2023-44487 | scada-plant-floor | 7.5 | 5.5 | -2.0 | isolated | high | HTTP/2 Rapid Reset - DDoS on SCADA Plant Controller. (isolated, high criticality). complia... |
| CVE-2026-45264 | web-payment-prod | 4.3 | 5.9 | +1.6 | public | high | Nextcloud SSRF on Payment Gateway (Prod). (public, high criticality). compliance: PCI-DSS,... |
| CVE-2026-45264 | db-customer-prod | 4.3 | 5.1 | +0.8 | internal | high | Nextcloud SSRF on Customer Database (Prod). (internal, high criticality). compliance: GDPR... |
| CVE-2026-45264 | web-corp-portal | 4.3 | 5.1 | +0.8 | public | medium | Nextcloud SSRF on Corporate Portal. (public, medium criticality). compliance: GDPR. threat... |
| CVE-2026-45264 | db-internal-dev | 4.3 | 3.0 | -1.3 | internal | low | Nextcloud SSRF on Dev Database Server. (internal, low criticality). threat 3.0/10 (lowered... |
| CVE-2026-45264 | iot-building-mgmt | 4.3 | 3.3 | -1.0 | isolated | medium | Nextcloud SSRF on Building Management. (isolated, medium criticality). threat 3.3/10 (lowe... |
| CVE-2026-45264 | ws-finance-prod | 4.3 | 4.8 | +0.5 | internal | high | Nextcloud SSRF on Finance Workstation. (internal, high criticality). compliance: SOX. thre... |
| CVE-2026-45264 | api-third-party | 4.3 | 5.1 | +0.8 | public | medium | Nextcloud SSRF on Third-Party Integration API. (public, medium criticality). compliance: G... |
| CVE-2026-45264 | scada-plant-floor | 4.3 | 4.1 | -0.2 | isolated | high | Nextcloud SSRF on SCADA Plant Controller. (isolated, high criticality). compliance: NIS2. ... |
| CVE-2018-1423 | web-payment-prod | 4.3 | 6.9 | +2.6 | public | high | IBM Jazz Info Disclosure on Payment Gateway (Prod). (public, high criticality). compliance... |
| CVE-2018-1423 | db-customer-prod | 4.3 | 6.1 | +1.8 | internal | high | IBM Jazz Info Disclosure on Customer Database (Prod). (internal, high criticality). compli... |
| CVE-2018-1423 | web-corp-portal | 4.3 | 6.1 | +1.8 | public | medium | IBM Jazz Info Disclosure on Corporate Portal. (public, medium criticality). compliance: GD... |
| CVE-2018-1423 | db-internal-dev | 4.3 | 4.0 | -0.3 | internal | low | IBM Jazz Info Disclosure on Dev Database Server. (internal, low criticality). threat 4.0/1... |
| CVE-2018-1423 | iot-building-mgmt | 4.3 | 4.3 | +0.0 | isolated | medium | IBM Jazz Info Disclosure on Building Management. (isolated, medium criticality). threat 4.... |
| CVE-2018-1423 | ws-finance-prod | 4.3 | 5.8 | +1.5 | internal | high | IBM Jazz Info Disclosure on Finance Workstation. (internal, high criticality). compliance:... |
| CVE-2018-1423 | api-third-party | 4.3 | 6.1 | +1.8 | public | medium | IBM Jazz Info Disclosure on Third-Party Integration API. (public, medium criticality). com... |
| CVE-2018-1423 | scada-plant-floor | 4.3 | 5.1 | +0.8 | isolated | high | IBM Jazz Info Disclosure on SCADA Plant Controller. (isolated, high criticality). complian... |
| CVE-2024-21626 | web-payment-prod | 8.6 | 8.9 | +0.3 | public | high | runc container escape (Leaky Vessels) on Payment Gateway (Prod). (public, high criticality... |
| CVE-2024-21626 | db-customer-prod | 8.6 | 8.1 | -0.5 | internal | high | runc container escape (Leaky Vessels) on Customer Database (Prod). (internal, high critica... |
| CVE-2024-21626 | web-corp-portal | 8.6 | 8.1 | -0.5 | public | medium | runc container escape (Leaky Vessels) on Corporate Portal. (public, medium criticality). c... |
| CVE-2024-21626 | db-internal-dev | 8.6 | 6.0 | -2.6 | internal | low | runc container escape (Leaky Vessels) on Dev Database Server. (internal, low criticality).... |
| CVE-2024-21626 | iot-building-mgmt | 8.6 | 6.3 | -2.3 | isolated | medium | runc container escape (Leaky Vessels) on Building Management. (isolated, medium criticalit... |
| CVE-2024-21626 | ws-finance-prod | 8.6 | 7.8 | -0.8 | internal | high | runc container escape (Leaky Vessels) on Finance Workstation. (internal, high criticality)... |
| CVE-2024-21626 | api-third-party | 8.6 | 8.1 | -0.5 | public | medium | runc container escape (Leaky Vessels) on Third-Party Integration API. (public, medium crit... |
| CVE-2024-21626 | scada-plant-floor | 8.6 | 7.1 | -1.5 | isolated | high | runc container escape (Leaky Vessels) on SCADA Plant Controller. (isolated, high criticali... |

---
## 4. Interpretazione

### Cosa significa il MAE

Un MAE di **1.08** indica che il LLM si discosta in media di 1.08 punti dal CVSS. 
Questo e' **atteso e desiderabile**: il sistema e' progettato per contestualizzare il rischio,
non per replicare il CVSS.

### Pattern osservati

- **Asset pubblici** (delta medio +0.24): il LLM tende a mantenere in linea il threat. **Pattern neutro.**
- **Asset interni** (delta medio -0.76): il LLM tende a abbassare il threat. **Pattern corretto.**
- **Asset isolati** (delta medio -1.36): il LLM tende a abbassare il threat. **Pattern corretto.**
- **Asset a alta criticità** (delta medio -0.13): il LLM tende a mantenere in linea il threat. **Pattern neutro.**
- **Asset a media criticità** (delta medio -0.56): il LLM tende a abbassare il threat. **Pattern corretto.**
- **Asset a bassa criticità** (delta medio -2.06): il LLM tende a abbassare il threat. **Pattern corretto.**

### Conclusione

Il sistema mostra una correlazione forte 
con il CVSS (r = 0.844) ma si discosta in modo **sistematico e giustificato** in base al contesto dell'asset.
I delta positivi per asset pubblici/critici e negativi per asset interni/bassa criticita' 
dimostrano che il LLM sta effettivamente contestualizzando il rischio.

**Campione:** 56 valutazioni su 8 asset e 7 CVE.
