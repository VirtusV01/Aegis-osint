# Aegis-osint

A research-grade, open-source OSINT investigation framework with temporal credibility modelling, noise-resilient entity correlation. Addresses the core limitations of existing tools such as Maltego and SpiderFoot — static credibility scoring, no temporal reasoning, and poor robustness under noisy data conditions.

---

## What This Is

Existing OSINT platforms assign credibility scores once at ingestion and never revise them. Aegis introduces three contributions that fix this:

| Contribution | Description |
|---|---|
| Temporal Credibility Decay | Exponential half-life model. Entities lose trust as they age. `credibility = 0.5 x corroboration + 0.3 x source_reputation + 0.2 x decay` |
| Credibility-Aware Correlation | Entity graph filters nodes below a configurable threshold (default 0.40). Edges carry credibility weights. |
| Noise Injection Evaluation | Controlled 30-cell experiment — 3 noise types x 5 contamination levels x 2 scoring modes. False positive rate = 0.000 across all cells. |

---

## Quick Start

### Prerequisites

- Python 3.11 or higher
- Git
- A Shodan API key (optional — required only for live scanning, not for synthetic demo mode)

### 1. Clone

```bash
git clone https://github.com/yourusername/aegis-osint.git
cd aegis-osint
```

### 2. Create virtual environment

```bash
# Windows
python -m venv .venv
.\.venv\Scripts\activate

# macOS / Linux
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

### 4. Configure environment

```bash
cp .env.example .env
```

Open `.env` and add your own API keys:

```env
# Required for live Shodan scanning only
# Get your free key at https://account.shodan.io
SHODAN_API_KEY=your_shodan_api_key_here
```

The framework runs fully without any API keys using Synthetic (Demo) mode. Live scanning requires a valid Shodan key.

### 5. Launch the dashboard

```bash
# Windows
.\.venv\Scripts\python.exe -m streamlit run src\osint\dashboard.py

# macOS / Linux
python -m streamlit run src/osint/dashboard.py
```

Open your browser at **http://localhost:8501**

---

## Project Structure

```
aegis-osint/
│
├── src/osint/
│   ├── services/
│   │   ├── credibility.py            # Temporal + static credibility scoring
│   │   ├── temporal_decay.py         # Exponential half-life decay model
│   │   ├── scanner.py                # Async scan orchestration
│   │   └── transforms.py             # Entity transformation pipeline
│   │
│   ├── modules/
│   │   ├── base.py                   # Abstract BaseModule
│   │   ├── sfp_shodan.py             # Shodan API integration
│   │   ├── sfp_whois_live.py         # Live WHOIS lookup
│   │   ├── sfp_dns_live.py           # DNS enumeration
│   │   └── sfp_http_live.py          # HTTP page fetching
│   │
│   ├── api/main.py                   # FastAPI REST endpoints
│   ├── nlp.py                        # spaCy NER + IOC regex extraction
│   ├── dedup.py                      # RapidFuzz fuzzy deduplication
│   ├── correlate.py                  # NetworkX credibility-aware graph
│   ├── normalizer.py                 # Record normalisation
│   ├── schemas.py                    # Entity / Record dataclasses
│   ├── storage_doc.py                # JSONL entity persistence
│   ├── storage_graph.py              # Graph pickle persistence
│   └── dashboard.py                  # Streamlit analyst dashboard
│
├── scripts/
│   ├── generate_synthetic_dataset.py # 50-record reproducible corpus (seed=42)
│   ├── noise_injection.py            # Controlled noise injection harness
│   └── run_evaluation.py             # 30-cell evaluation sweep
│
├── tests/
│   ├── test_temporal_decay.py        # 23 tests, all passing
│   ├── test_dedup.py
│   └── test_normalizer.py
│
├── data/
│   ├── samples/                      # Synthetic evaluation datasets
│   └── outputs/                      # Scan results and evaluation JSON
│
├── config.yaml                       # Module configuration
├── conftest.py                       # pytest path setup
├── requirements.txt
└── .env.example                      # API key template — do not commit .env
```

---

## OSINT Modules

| Module | Data Source | Reputation Weight |
|---|---|---|
| `sfp_shodan` | Shodan API — IP, port, banner intelligence | 0.85 |
| `sfp_whois_live` | Live WHOIS domain registration data | 0.70 |
| `sfp_dns_live` | DNS A / MX / NS / TXT record resolution | 0.65 |
| `sfp_http_live` | HTTP page fetch and text extraction | 0.60 |

---

## Credibility Model

### Temporal mode (default)

```
credibility = 0.5 x corroboration + 0.3 x source_reputation + 0.2 x decay
```

- **corroboration** = `min(1.0, distinct_source_count / 3)`
- **source_reputation** = fixed weight per module
- **decay** = `exp(-lambda x t)` where `lambda = ln(2) / half_life_days` (default: 30 days)

Decay behaviour:

| Entity Age | Decay Factor |
|---|---|
| 0 days | 1.000 |
| 30 days | 0.500 |
| 60 days | 0.250 |
| 90 days | 0.125 |

### Static mode (comparison baseline)

```
credibility = 0.6 x corroboration + 0.4 x source_reputation
```

### Switching modes

```python
from osint.services.credibility import compute_credibility

# Temporal (default)
entities = compute_credibility(entities, mode="temporal", half_life_days=30.0)

# Static baseline
entities = compute_credibility(entities, mode="static")
```

Every entity receives a full auditable breakdown in `meta.credibility_breakdown`:

```json
{
  "corroboration": 0.667,
  "source_reputation": 0.85,
  "decay_factor": 0.493,
  "age_days": 31.2,
  "half_life_days": 30.0,
  "formula": "0.5*corroboration + 0.3*source_reputation + 0.2*decay",
  "mode": "temporal"
}
```

---

## Evaluation Results

50-entity synthetic corpus, seed=42, 30 evaluation cells.

| Metric | Static | Temporal |
|---|---|---|
| Mean credibility gap | 0.1045 | 0.0653 |
| False positive rate (threshold 0.6) | 0.0000 | 0.0000 |
| Entities suppressed at 0% noise | 0 | 3 |
| Entities suppressed at 40% noise | 0 | 7 |
| Graph edge inflation at 40% noise | +39.1% | +26.1% |

Static scoring achieves a higher score-gap for analyst triage. Temporal scoring provides structural graph pruning — suppressing duplicate noise entities monotonically (3 to 7) as contamination grows from 0% to 40%. The two modes serve different operational contexts and are complementary.

### Run the evaluation

```bash
python scripts/generate_synthetic_dataset.py
python scripts/run_evaluation.py
# Results saved to data/outputs/evaluation_results.json
```

---

## Tests

```bash
# All tests
.\.venv\Scripts\python.exe -m pytest tests/ -v

# Temporal decay tests only (23 tests)
.\.venv\Scripts\python.exe -m pytest tests/test_temporal_decay.py -v
```

Test coverage includes decay factor boundary values, static vs temporal mode comparison, credibility breakdown structure, fuzzy deduplication, and entity normalisation.

---

## REST API

```bash
.\.venv\Scripts\python.exe -m uvicorn osint.api.main:app --reload --port 8000
```

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | System health check |
| `/modules` | GET | List registered OSINT modules |
| `/scans/start` | POST | Trigger a new scan |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.13 |
| NLP | spaCy en_core_web_sm + custom IOC regex |
| Deduplication | RapidFuzz (token_sort_ratio, threshold 90) |
| Graph | NetworkX |
| Dashboard | Streamlit + PyVis |
| API | FastAPI + Uvicorn |
| Charts | Plotly |
| Testing | pytest 9.x |
| External APIs | Shodan, python-whois, dnspython, requests |

---

## Roadmap

- [ ] Credibility-based node colour coding in entity graph (green / amber / red)
- [ ] Entity detail panel with full temporal breakdown on node click
- [ ] ROC curve analysis for threshold sensitivity
- [ ] PostgreSQL persistent storage backend
- [ ] Live threat feed integration (MISP, AlienVault OTX, CISA)
- [ ] Half-life parameter tuning per entity type
- [ ] Docker containerisation

---

## Ethical Use

This framework is for authorised security research and investigation only.

- Only scan systems and domains you own or have explicit written permission to investigate
- Use Synthetic (Demo) mode for evaluation and demonstration — no real network requests are made
- No personal data is collected or stored beyond local scan output files
- All evaluation datasets are synthetic and reproducible via seed=42
- Never commit your `.env` file or expose API keys in the repository

---

## Licence

MIT — see [LICENSE](LICENSE) for details.
