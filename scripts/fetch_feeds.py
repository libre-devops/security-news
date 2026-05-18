#!/usr/bin/env python3
"""
Microsoft Security News Feed Fetcher

What this does:
- Pulls real Microsoft security-related RSS feeds
- Normalizes entries
- Classifies articles into products and security domains
- Deduplicates by link
- Keeps only the last N days
- Writes:
  - data/feeds.json
  - data/feed.xml

Design goals:
- Config-driven sources
- Extensible product/domain taxonomy
- Aggressive-but-sane scoring
- Easy to add more feeds later without rewrites
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from html import unescape
from typing import Any, Dict, Iterable, List, Optional
from xml.etree.ElementTree import Element, SubElement, tostring

import feedparser

SITE_NAME = "Microsoft Security News"
SITE_URL = "https://security.libredevops.org"
SITE_DESCRIPTION = "Aggregated Microsoft security news and advisories"

MAX_ARTICLE_AGE_DAYS = 30
MAX_RSS_ITEMS = 100

# ---------------------------------------------------------------------------
# Source configuration
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Source:
    id: str
    name: str
    url: str
    vendor: str = "Microsoft"
    source_group: str = "Official Microsoft"
    source_kind: str = "rss"
    default_author: str = "Microsoft"
    category: str = "Security"
    board_id: Optional[str] = None
    max_entries: int = 20


SOURCES: List[Source] = [
    Source(
        id="mssecurity",
        name="Microsoft Security Blog",
        url="https://www.microsoft.com/security/blog/feed/",
        source_group="Official Microsoft",
        source_kind="rss",
        category="Security Blog",
    ),
    Source(
        id="msrc",
        name="Microsoft Security Response Center",
        url="https://api.msrc.microsoft.com/update-guide/rss",
        source_group="Official Microsoft",
        source_kind="rss",
        category="Advisories",
        max_entries=20,
    ),
    Source(
        id="sentinel",
        name="Microsoft Sentinel",
        url="https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=microsoftsentinelblog",
        source_group="TechCommunity",
        source_kind="techcommunity",
        board_id="microsoftsentinelblog",
        category="SIEM / SOAR",
    ),
    Source(
        id="defender_xdr",
        name="Microsoft Defender XDR",
        url="https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=microsoftthreatprotectionblog",
        source_group="TechCommunity",
        source_kind="techcommunity",
        board_id="microsoftthreatprotectionblog",
        category="XDR",
    ),
    Source(
        id="defender_cloud",
        name="Microsoft Defender for Cloud",
        url="https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=microsoftdefendercloudblog",
        source_group="TechCommunity",
        source_kind="techcommunity",
        board_id="microsoftdefendercloudblog",
        category="Cloud Security",
    ),
    Source(
        id="defender_endpoint",
        name="Microsoft Defender for Endpoint",
        url="https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=microsoftdefenderatpblog",
        source_group="TechCommunity",
        source_kind="techcommunity",
        board_id="microsoftdefenderatpblog",
        category="Endpoint Security",
    ),
    Source(
        id="defender_identity",
        name="Microsoft Defender for Identity",
        url="https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=azureadvancedthreatprotection",
        source_group="TechCommunity",
        source_kind="techcommunity",
        board_id="azureadvancedthreatprotection",
        category="Identity Security",
    ),
    Source(
        id="defender_office",
        name="Microsoft Defender for Office 365",
        url="https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=microsoftdefenderforoffice365blog",
        source_group="TechCommunity",
        source_kind="techcommunity",
        board_id="microsoftdefenderforoffice365blog",
        category="Email Security",
    ),
    Source(
        id="core_infra_security",
        name="Core Infrastructure & Security",
        url="https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=coreinfrastructureandsecurityblog",
        source_group="TechCommunity",
        source_kind="techcommunity",
        board_id="coreinfrastructureandsecurityblog",
        category="Security Operations",
    ),
    Source(
        id="network_security",
        name="Azure Network Security",
        url="https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=azurenetworksecurityblog",
        source_group="TechCommunity",
        source_kind="techcommunity",
        board_id="azurenetworksecurityblog",
        category="Network Security",
    ),
]

# ---------------------------------------------------------------------------
# Product taxonomy
# Aggressive-but-sane: weighted matching with thresholds
# ---------------------------------------------------------------------------

PRODUCTS: Dict[str, Dict[str, Any]] = {
    "defender-xdr": {
        "name": "Microsoft Defender XDR",
        "weight_threshold": 3,
        "patterns": [
            (r"\bmicrosoft defender xdr\b", 5),
            (r"\bdefender xdr\b", 4),
            (r"\bxdr\b", 2),
            (r"\bthreat protection\b", 1),
        ],
    },
    "defender-endpoint": {
        "name": "Microsoft Defender for Endpoint",
        "weight_threshold": 3,
        "patterns": [
            (r"\bmicrosoft defender for endpoint\b", 5),
            (r"\bdefender for endpoint\b", 4),
            (r"\bmde\b", 2),
            (r"\bendpoint detection and response\b", 1),
            (r"\bedr\b", 1),
        ],
    },
    "defender-identity": {
        "name": "Microsoft Defender for Identity",
        "weight_threshold": 3,
        "patterns": [
            (r"\bmicrosoft defender for identity\b", 5),
            (r"\bdefender for identity\b", 4),
            (r"\bmdi\b", 2),
            (r"\bidentity protection\b", 1),
        ],
    },
    "defender-cloud-apps": {
        "name": "Microsoft Defender for Cloud Apps",
        "weight_threshold": 3,
        "patterns": [
            (r"\bmicrosoft defender for cloud apps\b", 5),
            (r"\bdefender for cloud apps\b", 4),
            (r"\bmdca\b", 2),
            (r"\bcasb\b", 1),
        ],
    },
    "defender-office": {
        "name": "Microsoft Defender for Office 365",
        "weight_threshold": 3,
        "patterns": [
            (r"\bmicrosoft defender for office 365\b", 5),
            (r"\bdefender for office 365\b", 4),
            (r"\bdefender for office\b", 3),
            (r"\bexchange online protection\b", 1),
            (r"\bphishing protection\b", 1),
        ],
    },
    "defender-cloud": {
        "name": "Microsoft Defender for Cloud",
        "weight_threshold": 3,
        "patterns": [
            (r"\bmicrosoft defender for cloud\b", 5),
            (r"\bdefender for cloud\b", 4),
            (r"\bmdc\b", 2),
            (r"\bcloud security posture management\b", 1),
            (r"\bcspm\b", 1),
        ],
    },
    "sentinel": {
        "name": "Microsoft Sentinel",
        "weight_threshold": 3,
        "patterns": [
            (r"\bmicrosoft sentinel\b", 5),
            (r"\bsentinel\b", 4),
            (r"\bsiem\b", 2),
            (r"\bsoar\b", 2),
        ],
    },
    "entra": {
        "name": "Microsoft Entra",
        "weight_threshold": 3,
        "patterns": [
            (r"\bmicrosoft entra\b", 5),
            (r"\bentra id\b", 4),
            (r"\bazure ad\b", 3),
            (r"\bidentity and access management\b", 1),
        ],
    },
    "purview": {
        "name": "Microsoft Purview",
        "weight_threshold": 3,
        "patterns": [
            (r"\bmicrosoft purview\b", 5),
            (r"\bpurview\b", 4),
            (r"\bdata governance\b", 1),
            (r"\bcompliance\b", 1),
        ],
    },
    "intune": {
        "name": "Microsoft Intune",
        "weight_threshold": 3,
        "patterns": [
            (r"\bmicrosoft intune\b", 5),
            (r"\bintune\b", 4),
            (r"\bmdm\b", 1),
            (r"\bendpoint management\b", 1),
        ],
    },
    "msrc": {
        "name": "Microsoft Security Response Center",
        "weight_threshold": 3,
        "patterns": [
            (r"\bmsrc\b", 5),
            (r"\bmicrosoft security response center\b", 5),
            (r"\bsecurity advisory\b", 2),
            (r"\bcve-\d{4}-\d+\b", 2),
        ],
    },
    "general-security": {
        "name": "General Security",
        "weight_threshold": 1,
        "patterns": [],
    },
}

# ---------------------------------------------------------------------------
# Domain taxonomy
# Domains are allowed to be broader than products.
# We derive them from product matches and also from direct keyword matching.
# ---------------------------------------------------------------------------

DOMAINS: Dict[str, Dict[str, Any]] = {
    "identity-security": {
        "name": "Identity Security",
        "weight_threshold": 2,
        "patterns": [
            (r"\bentra id\b", 3),
            (r"\bidentity\b", 2),
            (r"\bauthentication\b", 1),
            (r"\bauthorization\b", 1),
            (r"\bconditional access\b", 2),
        ],
    },
    "endpoint-security": {
        "name": "Endpoint Security",
        "weight_threshold": 2,
        "patterns": [
            (r"\bendpoint\b", 2),
            (r"\bedr\b", 2),
            (r"\bdefender for endpoint\b", 4),
            (r"\bmde\b", 2),
        ],
    },
    "email-security": {
        "name": "Email Security",
        "weight_threshold": 2,
        "patterns": [
            (r"\bemail\b", 1),
            (r"\bphishing\b", 2),
            (r"\bmicrosoft defender for office 365\b", 4),
            (r"\boffice 365\b", 2),
        ],
    },
    "cloud-security": {
        "name": "Cloud Security",
        "weight_threshold": 2,
        "patterns": [
            (r"\bcloud\b", 1),
            (r"\bdefender for cloud\b", 4),
            (r"\bcspm\b", 2),
            (r"\bcasb\b", 2),
        ],
    },
    "siem-xdr": {
        "name": "SIEM / XDR",
        "weight_threshold": 2,
        "patterns": [
            (r"\bsiem\b", 3),
            (r"\bsoar\b", 2),
            (r"\bxdr\b", 3),
            (r"\bsentinel\b", 4),
        ],
    },
    "threat-intelligence": {
        "name": "Threat Intelligence",
        "weight_threshold": 2,
        "patterns": [
            (r"\bthreat intelligence\b", 4),
            (r"\bthreat actor\b", 2),
            (r"\bmalware\b", 2),
            (r"\bphishing\b", 1),
            (r"\bib\b", 1),
        ],
    },
    "incident-response": {
        "name": "Incident Response",
        "weight_threshold": 2,
        "patterns": [
            (r"\bincident response\b", 4),
            (r"\bresponse\b", 1),
            (r"\bcontainment\b", 1),
            (r"\bforensics\b", 1),
        ],
    },
    "governance-compliance": {
        "name": "Governance / Compliance",
        "weight_threshold": 2,
        "patterns": [
            (r"\bcompliance\b", 2),
            (r"\bgov(ernance)?\b", 1),
            (r"\bpurview\b", 3),
            (r"\baudit\b", 1),
        ],
    },
    "vulnerability-management": {
        "name": "Vulnerability Management",
        "weight_threshold": 2,
        "patterns": [
            (r"\bcve-\d{4}-\d+\b", 3),
            (r"\bvulnerability\b", 2),
            (r"\bpatch\b", 1),
            (r"\bexploitation\b", 1),
        ],
    },
    "security-operations": {
        "name": "Security Operations",
        "weight_threshold": 2,
        "patterns": [
            (r"\bsecurity operations\b", 3),
            (r"\bsoc\b", 2),
            (r"\bhunting\b", 1),
            (r"\bdetection\b", 1),
            (r"\btelemetry\b", 1),
        ],
    },
    "general-security": {
        "name": "General Security",
        "weight_threshold": 1,
        "patterns": [],
    },
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def clean_html(text: str) -> str:
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", "", text)
    text = unescape(text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def truncate(text: str, max_length: int = 300) -> str:
    if len(text) <= max_length:
        return text
    return text[:max_length].rsplit(" ", 1)[0] + "..."


def parse_date(entry: Any) -> str:
    for field in ("published_parsed", "updated_parsed"):
        parsed = entry.get(field)
        if parsed:
            try:
                dt = datetime(*parsed[:6], tzinfo=timezone.utc)
                return dt.isoformat()
            except (ValueError, TypeError):
                pass

    for field in ("published", "updated"):
        value = entry.get(field)
        if value:
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                return parsed.astimezone(timezone.utc).isoformat()
            except ValueError:
                return value

    return datetime.now(timezone.utc).isoformat()


def _weighted_match(text: str, patterns: List[tuple[str, int]]) -> int:
    score = 0
    for pattern, weight in patterns:
        if re.search(pattern, text, flags=re.IGNORECASE):
            score += weight
    return score


def classify_products(title: str, summary: str, source_name: str = "") -> List[dict]:
    text = f"{title} {summary} {source_name}".lower()

    matches = []
    for product_id, cfg in PRODUCTS.items():
        if product_id == "general-security":
            continue
        score = _weighted_match(text, cfg["patterns"])
        if score >= cfg["weight_threshold"]:
            matches.append(
                {
                    "id": product_id,
                    "name": cfg["name"],
                    "score": score,
                }
            )

    if not matches:
        matches.append(
            {
                "id": "general-security",
                "name": PRODUCTS["general-security"]["name"],
                "score": 1,
            }
        )

    matches.sort(key=lambda x: (-x["score"], x["name"]))
    return matches


def classify_domains(
    title: str,
    summary: str,
    products: List[dict],
    source_name: str = "",
) -> List[dict]:
    text = f"{title} {summary} {source_name}".lower()

    domain_scores: Dict[str, int] = {}

    # Direct domain matching
    for domain_id, cfg in DOMAINS.items():
        if domain_id == "general-security":
            continue
        score = _weighted_match(text, cfg["patterns"])
        if score >= cfg["weight_threshold"]:
            domain_scores[domain_id] = score

    # Derive domains from product matches
    product_ids = {p["id"] for p in products}

    if "sentinel" in product_ids:
        domain_scores["siem-xdr"] = max(domain_scores.get("siem-xdr", 0), 4)
        domain_scores["security-operations"] = max(
            domain_scores.get("security-operations", 0), 2
        )

    if "defender-xdr" in product_ids:
        domain_scores["siem-xdr"] = max(domain_scores.get("siem-xdr", 0), 3)
        domain_scores["security-operations"] = max(
            domain_scores.get("security-operations", 0), 2
        )

    if "defender-endpoint" in product_ids:
        domain_scores["endpoint-security"] = max(
            domain_scores.get("endpoint-security", 0), 4
        )

    if "defender-identity" in product_ids or "entra" in product_ids:
        domain_scores["identity-security"] = max(
            domain_scores.get("identity-security", 0), 4
        )

    if "defender-office" in product_ids:
        domain_scores["email-security"] = max(
            domain_scores.get("email-security", 0), 4
        )

    if "defender-cloud" in product_ids or "defender-cloud-apps" in product_ids:
        domain_scores["cloud-security"] = max(
            domain_scores.get("cloud-security", 0), 4
        )

    if "purview" in product_ids:
        domain_scores["governance-compliance"] = max(
            domain_scores.get("governance-compliance", 0), 4
        )

    if "msrc" in product_ids:
        domain_scores["vulnerability-management"] = max(
            domain_scores.get("vulnerability-management", 0), 4
        )

    if not domain_scores:
        domain_scores["general-security"] = 1

    result = []
    for domain_id, score in domain_scores.items():
        if domain_id in DOMAINS:
            result.append(
                {
                    "id": domain_id,
                    "name": DOMAINS[domain_id]["name"],
                    "score": score,
                }
            )

    result.sort(key=lambda x: (-x["score"], x["name"]))
    return result


def normalize_entry(entry: Any, source: Source) -> dict:
    title = clean_html(entry.get("title", "Untitled"))
    summary_raw = clean_html(entry.get("summary", ""))
    summary = truncate(summary_raw)

    products = classify_products(title, summary_raw, source.name)
    domains = classify_domains(title, summary_raw, products, source.name)

    return {
        "title": title,
        "link": entry.get("link", ""),
        "published": parse_date(entry),
        "summary": summary,
        "author": entry.get("author", source.default_author),
        "source": source.name,
        "source_id": source.id,
        "source_group": source.source_group,
        "source_kind": source.source_kind,
        "vendor": source.vendor,
        "source_category": source.category,
        "board_id": source.board_id,
        "products": products,
        "domains": domains,
        "tags": [p["name"] for p in products] + [d["name"] for d in domains],
    }


def fetch_feed(source: Source) -> List[dict]:
    print(f"Fetching: {source.name}")

    try:
        feed = feedparser.parse(source.url)

        if feed.bozo and not feed.entries:
            print(f"  Failed to parse {source.name}")
            return []

        articles = []
        entries = feed.entries[:source.max_entries]

        for entry in entries:
            articles.append(normalize_entry(entry, source))

        print(f"  Found {len(articles)} articles")
        return articles

    except Exception as ex:
        print(f"  Error fetching {source.name}: {ex}")
        return []


def deduplicate_articles(articles: List[dict]) -> List[dict]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=MAX_ARTICLE_AGE_DAYS)

    seen_links = set()
    unique = []

    for article in articles:
        link = article.get("link", "")
        published = article.get("published", "")

        if not link or link in seen_links:
            continue

        try:
            published_dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
        except ValueError:
            continue

        if published_dt < cutoff:
            continue

        seen_links.add(link)
        unique.append(article)

    return unique


def generate_json_feed(articles: List[dict]) -> None:
    os.makedirs("data", exist_ok=True)

    payload = {
        "site": SITE_NAME,
        "lastUpdated": datetime.now(timezone.utc).isoformat(),
        "totalArticles": len(articles),
        "articles": articles,
    }

    output = os.path.join("data", "feeds.json")
    with open(output, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    print(f"JSON feed written to {output}")


def generate_rss_feed(articles: List[dict]) -> None:
    rss = Element("rss", version="2.0")
    rss.set("xmlns:dc", "http://purl.org/dc/elements/1.1/")

    channel = SubElement(rss, "channel")
    SubElement(channel, "title").text = SITE_NAME
    SubElement(channel, "link").text = SITE_URL
    SubElement(channel, "description").text = SITE_DESCRIPTION
    SubElement(channel, "generator").text = "Microsoft Security News Feed"
    SubElement(channel, "language").text = "en"
    SubElement(channel, "lastBuildDate").text = datetime.now(
        timezone.utc
    ).strftime("%a, %d %b %Y %H:%M:%S GMT")

    for article in articles[:MAX_RSS_ITEMS]:
        item = SubElement(channel, "item")
        SubElement(item, "title").text = article["title"]
        SubElement(item, "link").text = article["link"]
        SubElement(item, "guid").text = article["link"]
        SubElement(item, "description").text = article["summary"]
        SubElement(item, "dc:creator").text = article["author"]

        categories = article.get("products", [])
        if categories:
            for product in categories:
                SubElement(item, "category").text = product["name"]
        else:
            SubElement(item, "category").text = article.get("source_category", "Security")

        # Add domains as extra categories too
        for domain in article.get("domains", []):
            SubElement(item, "category").text = domain["name"]

        try:
            dt = datetime.fromisoformat(article["published"].replace("Z", "+00:00"))
            SubElement(item, "pubDate").text = dt.strftime("%a, %d %b %Y %H:%M:%S GMT")
        except ValueError:
            pass

    xml = '<?xml version="1.0" encoding="UTF-8"?>\n' + tostring(rss, encoding="unicode")

    output = os.path.join("data", "feed.xml")
    with open(output, "w", encoding="utf-8") as f:
        f.write(xml)

    print(f"RSS feed written to {output}")


def main() -> None:
    print("=" * 60)
    print(SITE_NAME)
    print("=" * 60)

    all_articles: List[dict] = []

    for source in SOURCES:
        all_articles.extend(fetch_feed(source))

    # Sort newest first
    all_articles.sort(key=lambda x: x.get("published", ""), reverse=True)

    # Deduplicate and age filter
    unique_articles = deduplicate_articles(all_articles)

    generate_json_feed(unique_articles)
    generate_rss_feed(unique_articles)

    print("=" * 60)
    print(f"Done. {len(unique_articles)} articles generated.")
    print("=" * 60)


if __name__ == "__main__":
    main()