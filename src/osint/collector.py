from loguru import logger
from datetime import datetime
import requests, whois, tldextract
from .schemas import Record

def fetch_web(url: str) -> Record:
    r = requests.get(url, timeout=10)
    r.raise_for_status()
    title = None
    if "<title>" in r.text.lower():
        try:
            title = r.text.split("<title>")[1].split("</title>")[0][:200]
        except Exception:
            title = None
    rec = Record(
        source="web",
        fetched_at=datetime.utcnow().isoformat(),
        url=url,
        title=title,
        text=r.text[:5000]   # keep it small for IPR demo
    )
    logger.info(f"Fetched {url}")
    return rec

def fetch_whois(domain_or_url: str) -> Record:
    domain = tldextract.extract(domain_or_url)
    q = ".".join([p for p in [domain.domain, domain.suffix] if p])
    w = whois.whois(q)
    return Record(
        source="whois",
        fetched_at=datetime.utcnow().isoformat(),
        url=f"whois://{q}",
        whois={k: (str(v)[:500] if isinstance(v, (list, set)) else str(v)[:500]) for k,v in w.__dict__.items()}
    )
