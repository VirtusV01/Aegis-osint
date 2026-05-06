"""
Generate a 50-record synthetic OSINT entity dataset for evaluation experiments.

Records are in entity format (type/value/provenance/last_seen/record_id) so they
feed directly into compute_credibility() without an extraction step.

Design choices for research validity:
  - Fixed seed for reproducibility
  - Age range 0-90 days to exercise temporal decay across the full dynamic range
  - Corroborated entities (same type+value from multiple provenances) simulate real
    cross-source confirmation and drive corroboration scores above 0.33
  - All four provenance tiers are represented so SOURCE_REPUTATION has full coverage
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timezone, timedelta
from pathlib import Path

SEED = 42
random.seed(SEED)

# ---------------------------------------------------------------------------
# Entity pools
# ---------------------------------------------------------------------------

IP_POOL = [
    "192.168.1.1", "10.0.0.5", "45.33.32.156", "104.21.1.1",
    "185.220.101.5", "198.51.100.3", "203.0.113.7", "8.8.4.4",
    "1.1.1.1", "66.249.64.1", "91.108.4.1", "77.88.8.8",
]

DOMAIN_POOL = [
    "example.com", "cyberwatch.io", "securedata.net", "darktrace.ai",
    "malicious-host.ru", "phishing-site.tk", "threat-intel.org",
    "apt-c2.xyz", "legitimate-corp.com", "dark-forum.cc",
]

EMAIL_POOL = [
    "alice@cyberwatch.io", "info@securedata.net", "support@darktrace.ai",
    "admin@example.com", "root@malicious-host.ru", "admin@apt-c2.xyz",
    "contact@threat-intel.org", "abuse@legitimate-corp.com",
    "noreply@dark-forum.cc", "sec@cyberwatch.io",
]

PERSON_POOL = [
    "Alice Johnson", "Robert Mills", "Samantha Lee", "David Carter",
    "Ivan Petrov", "Zhang Wei", "Fatima Al-Hassan",
]

ORG_POOL = [
    "ThreatCorp LLC", "CyberWatch Solutions", "APT Group 29",
    "Secure Analytics Inc", "Dark Net Collective", "Global Threat Intel",
]

REGIONS = ["US", "EU", "RU", "CN", "APAC", "LATAM"]


def _ago(days: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def _rec(counter: list, *, entity_type: str, value: str, provenance: str,
         age_days: float, extra_meta: dict | None = None) -> dict:
    n = counter[0]
    counter[0] += 1
    return {
        "record_id": f"rec_{n:05d}",
        "type": entity_type,
        "value": value,
        "provenance": provenance,
        "last_seen": _ago(age_days),
        "meta": extra_meta or {},
    }


def build_records() -> list[dict]:
    ctr = [0]
    records: list[dict] = []

    # ------------------------------------------------------------------
    # IPs — sfp_shodan is primary; 5 of them also appear via correlate
    # (corroboration). Ages 0-60 days.
    # ------------------------------------------------------------------
    shodan_ips = IP_POOL[:6]
    for i, ip in enumerate(shodan_ips):
        records.append(_rec(ctr, entity_type="ip", value=ip,
                            provenance="sfp_shodan",
                            age_days=round(random.uniform(0, 40), 1),
                            extra_meta={"region": random.choice(REGIONS)}))

    for ip in shodan_ips[:4]:          # 4 corroborated via correlate
        records.append(_rec(ctr, entity_type="ip", value=ip,
                            provenance="correlate",
                            age_days=round(random.uniform(5, 60), 1)))

    for ip in IP_POOL[6:9]:            # 3 IPs only from records_synth
        records.append(_rec(ctr, entity_type="ip", value=ip,
                            provenance="records_synth",
                            age_days=round(random.uniform(10, 90), 1)))

    # ------------------------------------------------------------------
    # Domains — whois_synth primary; 4 also via sfp_shodan. Ages 0-90 d.
    # ------------------------------------------------------------------
    whois_domains = DOMAIN_POOL[:7]
    for dom in whois_domains:
        records.append(_rec(ctr, entity_type="domain", value=dom,
                            provenance="whois_synth",
                            age_days=round(random.uniform(0, 50), 1)))

    for dom in whois_domains[:4]:      # 4 corroborated via sfp_shodan
        records.append(_rec(ctr, entity_type="domain", value=dom,
                            provenance="sfp_shodan",
                            age_days=round(random.uniform(5, 45), 1)))

    for dom in DOMAIN_POOL[7:]:        # 3 only from records_synth, old
        records.append(_rec(ctr, entity_type="domain", value=dom,
                            provenance="records_synth",
                            age_days=round(random.uniform(30, 90), 1)))

    # ------------------------------------------------------------------
    # Emails — records_synth primary; 4 also via correlate. Ages 0-60 d.
    # ------------------------------------------------------------------
    for email in EMAIL_POOL[:6]:
        records.append(_rec(ctr, entity_type="email", value=email,
                            provenance="records_synth",
                            age_days=round(random.uniform(0, 50), 1)))

    for email in EMAIL_POOL[:4]:       # 4 corroborated via correlate
        records.append(_rec(ctr, entity_type="email", value=email,
                            provenance="correlate",
                            age_days=round(random.uniform(5, 60), 1)))

    # ------------------------------------------------------------------
    # Persons — whois_synth and correlate. Ages 10-90 d.
    # ------------------------------------------------------------------
    for person in PERSON_POOL[:4]:
        records.append(_rec(ctr, entity_type="person", value=person,
                            provenance="whois_synth",
                            age_days=round(random.uniform(10, 70), 1)))

    for person in PERSON_POOL[4:]:
        records.append(_rec(ctr, entity_type="person", value=person,
                            provenance="correlate",
                            age_days=round(random.uniform(20, 90), 1)))

    # ------------------------------------------------------------------
    # Orgs — mixed provenances. Ages 0-60 d.
    # ------------------------------------------------------------------
    for org in ORG_POOL[:3]:
        records.append(_rec(ctr, entity_type="org", value=org,
                            provenance="whois_synth",
                            age_days=round(random.uniform(0, 45), 1)))

    for org in ORG_POOL[3:]:
        records.append(_rec(ctr, entity_type="org", value=org,
                            provenance="records_synth",
                            age_days=round(random.uniform(5, 30), 1)))

    assert len(records) == 50, f"Expected 50 records, got {len(records)}"
    return records


def main() -> None:
    records = build_records()
    output_path = Path("data/samples/synthetic_records.jsonl")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"Generated {len(records)} entity records -> {output_path}")
    type_counts = {}
    for r in records:
        type_counts[r["type"]] = type_counts.get(r["type"], 0) + 1
    for t, c in sorted(type_counts.items()):
        print(f"  {t:<10} {c} records")


if __name__ == "__main__":
    main()
