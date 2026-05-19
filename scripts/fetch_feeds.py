#!/usr/bin/env python3
"""
Microsoft Security News Feed Fetcher
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from html import unescape
from typing import Any, Dict, List, Optional
from xml.etree.ElementTree import Element, SubElement, tostring

import feedparser

SITE_NAME = "Microsoft Security News"
SITE_URL = "https://security.libredevops.org"
SITE_DESCRIPTION = "Aggregated Microsoft security news and advisories"

MAX_ARTICLE_AGE_DAYS = 30
MAX_RSS_ITEMS = 100


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
    max_entries: int = 25


SOURCES: List[Source] = [
    Source(
        id="mssecurity",
        name="Microsoft Security Blog",
        url="https://www.microsoft.com/security/blog/feed/",
        category="Security Blog",
    ),
    Source(
        id="msrc",
        name="Microsoft Security Response Center",
        url="https://api.msrc.microsoft.com/update-guide/rss",
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
        id="security_copilot",
        name="Microsoft Security Copilot",
        url="https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=SecurityCopilotBlog",
        source_group="TechCommunity",
        source_kind="techcommunity",
        board_id="securitycopilot",
        category="AI Security",
    ),
    Source(
        id="threat_intel",
        name="Microsoft Threat Intelligence",
        url="https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/feed/",
        category="Threat Intelligence",
    ),
    Source(
        id="purview",
        name="Microsoft Purview",
        url="https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=microsoft-purview-blog",
        source_group="TechCommunity",
        source_kind="techcommunity",
        board_id="microsoftpurviewblog",
        category="Data Security",
    ),
    Source(
        id="ms_ai_blog",
        name="Microsoft AI Blog",
        url="https://blogs.microsoft.com/feed/",
        category="AI",
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

PRODUCTS: Dict[str, Dict[str, Any]] = {
    "defender-xdr": {
        "name": "Microsoft Defender XDR",
        "weight_threshold": 3,
        "patterns": [
            (r"\bmicrosoft defender xdr\b", 5),
            (r"\bdefender xdr\b", 4),
            (r"\bxdr\b", 2),
        ],
    },
    "defender-endpoint": {
        "name": "Microsoft Defender for Endpoint",
        "weight_threshold": 3,
        "patterns": [
            (r"\bmicrosoft defender for endpoint\b", 5),
            (r"\bdefender for endpoint\b", 4),
            (r"\bmde\b", 2),
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
        ],
    },
    "defender-cloud-apps": {
        "name": "Microsoft Defender for Cloud Apps",
        "weight_threshold": 3,
        "patterns": [
            (r"\bmicrosoft defender for cloud apps\b", 5),
            (r"\bdefender for cloud apps\b", 4),
            (r"\bmdca\b", 2),
        ],
    },
    "defender-office": {
        "name": "Microsoft Defender for Office 365",
        "weight_threshold": 3,
        "patterns": [
            (r"\bmicrosoft defender for office 365\b", 5),
            (r"\bdefender for office 365\b", 4),
        ],
    },
    "defender-cloud": {
        "name": "Microsoft Defender for Cloud",
        "weight_threshold": 3,
        "patterns": [
            (r"\bmicrosoft defender for cloud\b", 5),
            (r"\bdefender for cloud\b", 4),
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
    "security-copilot": {
        "name": "Microsoft Security Copilot",
        "weight_threshold": 3,
        "patterns": [
            (r"\bmicrosoft security copilot\b", 5),
            (r"\bsecurity copilot\b", 4),
        ],
    },
    "threat-intelligence": {
        "name": "Threat Intelligence",
        "weight_threshold": 2,
        "patterns": [
            (r"\bthreat intelligence\b", 5),
            (r"\bthreat actor\b", 3),
            (r"\bmalware\b", 2),
            (r"\bransomware\b", 2),
            (r"\bapt\b", 2),
            (r"\bcampaign\b", 1),
        ],
    },
    "purview": {
        "name": "Microsoft Purview",
        "weight_threshold": 2,
        "patterns": [
            (r"\bmicrosoft purview\b", 5),
            (r"\bpurview\b", 4),
            (r"\bdlp\b", 2),
            (r"\binsider risk\b", 2),
            (r"\bdata governance\b", 2),
        ],
    },
    "ai-security": {
        "name": "AI Security",
        "weight_threshold": 2,
        "patterns": [
            (r"\bai security\b", 4),
            (r"\bllm security\b", 3),
            (r"\bprompt injection\b", 2),
            (r"\bgenerative ai\b", 1),
        ],
    },
    "general-security": {
        "name": "General Security",
        "weight_threshold": 1,
        "patterns": [],
    },
}


def clean_html(text: str) -> str:
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", "", text)
    text = unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def truncate(text: str, max_length: int = 300) -> str:
    if len(text) <= max_length:
        return text
    return text[:max_length].rsplit(" ", 1)[0] + "..."


def parse_date(entry: Any) -> str:
    parsed = entry.get("published_parsed") or entry.get("updated_parsed")
    if parsed:
        dt = datetime(*parsed[:6], tzinfo=timezone.utc)
        return dt.isoformat()
    return datetime.now(timezone.utc).isoformat()


def weighted_match(text: str, patterns: List[tuple]) -> int:
    score = 0
    for pattern, weight in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            score += weight
    return score


def classify_products(title: str, summary: str, source_name: str = "") -> List[dict]:
    text = f"{title} {summary} {source_name}".lower()
    matches = []

    for product_id, cfg in PRODUCTS.items():
        if product_id == "general-security":
            continue

        score = weighted_match(text, cfg["patterns"])

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
                "name": "General Security",
                "score": 1,
            }
        )

    matches.sort(key=lambda x: (-x["score"], x["name"]))
    return matches


def normalize_entry(entry: Any, source: Source) -> Optional[dict]:
    title = clean_html(entry.get("title", "Untitled"))
    summary_raw = clean_html(entry.get("summary", ""))

    if source.id == "msrc" and re.match(r"^CVE-\d{4}-\d+", title, re.IGNORECASE):
        return None

    summary = truncate(summary_raw)
    products = classify_products(title, summary_raw, source.name)

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
        "tags": [p["name"] for p in products],
    }


def fetch_feed(source: Source) -> List[dict]:
    print(f"Fetching: {source.name}")

    try:
        feed = feedparser.parse(source.url)
        articles = []

        for entry in feed.entries[: source.max_entries]:
            article = normalize_entry(entry, source)
            if article:
                articles.append(article)

        print(f"  Found {len(articles)} articles")
        print(f"  Feed contains {len(feed.entries)} raw entries")
        return articles

    except Exception as ex:
        print(f"  Error fetching {source.name}: {ex}")
        return []


def deduplicate_articles(articles: List[dict]) -> List[dict]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=MAX_ARTICLE_AGE_DAYS)

    seen = set()
    unique = []

    for article in articles:
        if article["link"] in seen:
            continue

        published = datetime.fromisoformat(article["published"])
        if published < cutoff:
            continue

        seen.add(article["link"])
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

    with open("data/feeds.json", "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def generate_rss_feed(articles: List[dict]) -> None:
    rss = Element("rss", version="2.0")
    channel = SubElement(rss, "channel")

    SubElement(channel, "title").text = SITE_NAME
    SubElement(channel, "link").text = SITE_URL
    SubElement(channel, "description").text = SITE_DESCRIPTION

    for article in articles[:MAX_RSS_ITEMS]:
        item = SubElement(channel, "item")
        SubElement(item, "title").text = article["title"]
        SubElement(item, "link").text = article["link"]
        SubElement(item, "description").text = article["summary"]

        for product in article["products"]:
            SubElement(item, "category").text = product["name"]

    xml = '<?xml version="1.0" encoding="UTF-8"?>\n' + tostring(rss, encoding="unicode")

    with open("data/feed.xml", "w", encoding="utf-8") as f:
        f.write(xml)


def main():
    print("=" * 60)
    print(SITE_NAME)
    print("=" * 60)

    articles = []

    for source in SOURCES:
        articles.extend(fetch_feed(source))

    articles.sort(key=lambda x: x["published"], reverse=True)
    articles = deduplicate_articles(articles)

    generate_json_feed(articles)
    generate_rss_feed(articles)

    print("=" * 60)
    print(f"Done. {len(articles)} articles generated.")
    print("=" * 60)


if __name__ == "__main__":
    main()