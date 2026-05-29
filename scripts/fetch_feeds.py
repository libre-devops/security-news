#!/usr/bin/env python3
"""
Security News Feed Fetcher
"""

from __future__ import annotations

import json
import os
import re
import socket
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from html import unescape
from typing import Any, Dict, List, Optional, Tuple
from xml.etree.ElementTree import Element, SubElement, tostring  # nosec B405

import feedparser

SITE_NAME = "Security News"
SITE_URL = "https://security.libredevops.org"
SITE_DESCRIPTION = (
    "Aggregated public security news, advisories, and threat intelligence"
)

MAX_ARTICLE_AGE_DAYS = 30
MAX_RSS_ITEMS = 100
DATA_FILE = "data/feeds.json"

# Per-request socket timeout (seconds). feedparser uses urllib under the hood,
# which has no default timeout — without this a single hung feed would stall
# the whole run until the CI job-level timeout kills it.
FEED_TIMEOUT_SECONDS = 20


@dataclass(frozen=True)
class Source:
    id: str
    name: str
    url: str
    vendor: str = "Security"
    source_group: str = "Official"
    source_kind: str = "rss"
    default_author: str = "Security Vendor"
    category: str = "Security"
    board_id: Optional[str] = None
    max_entries: int = 25


SOURCES: List[Source] = [
    Source(
        id="mssecurity",
        name="Microsoft Security Blog",
        url="https://www.microsoft.com/security/blog/feed/",
        vendor="Microsoft",
        default_author="Microsoft",
        source_group="Official Microsoft",
        category="Security Blog",
    ),
    Source(
        id="msrc",
        name="Microsoft Security Response Center",
        url="https://api.msrc.microsoft.com/update-guide/rss",
        vendor="Microsoft",
        default_author="Microsoft",
        source_group="Official Microsoft",
        category="Advisories",
        max_entries=20,
    ),
    Source(
        id="sentinel",
        name="Microsoft Sentinel",
        url="https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=microsoftsentinelblog",
        vendor="Microsoft",
        default_author="Microsoft",
        source_group="TechCommunity",
        source_kind="techcommunity",
        board_id="microsoftsentinelblog",
        category="SIEM / SOAR",
    ),
    Source(
        id="defender_xdr",
        name="Microsoft Defender XDR",
        url="https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=microsoftthreatprotectionblog",
        vendor="Microsoft",
        default_author="Microsoft",
        source_group="TechCommunity",
        source_kind="techcommunity",
        board_id="microsoftthreatprotectionblog",
        category="XDR",
    ),
    Source(
        id="defender_cloud",
        name="Microsoft Defender for Cloud",
        url="https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=microsoftdefendercloudblog",
        vendor="Microsoft",
        default_author="Microsoft",
        source_group="TechCommunity",
        source_kind="techcommunity",
        board_id="microsoftdefendercloudblog",
        category="Cloud Security",
    ),
    Source(
        id="defender_endpoint",
        name="Microsoft Defender for Endpoint",
        url="https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=microsoftdefenderatpblog",
        vendor="Microsoft",
        default_author="Microsoft",
        source_group="TechCommunity",
        source_kind="techcommunity",
        board_id="microsoftdefenderatpblog",
        category="Endpoint Security",
    ),
    Source(
        id="defender_identity",
        name="Microsoft Defender for Identity",
        url="https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=azureadvancedthreatprotection",
        vendor="Microsoft",
        default_author="Microsoft",
        source_group="TechCommunity",
        source_kind="techcommunity",
        board_id="azureadvancedthreatprotection",
        category="Identity Security",
    ),
    Source(
        id="defender_office",
        name="Microsoft Defender for Office 365",
        url="https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=microsoftdefenderforoffice365blog",
        vendor="Microsoft",
        default_author="Microsoft",
        source_group="TechCommunity",
        source_kind="techcommunity",
        board_id="microsoftdefenderforoffice365blog",
        category="Email Security",
    ),
    Source(
        id="security_copilot",
        name="Microsoft Security Copilot",
        url="https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=SecurityCopilotBlog",
        vendor="Microsoft",
        default_author="Microsoft",
        source_group="TechCommunity",
        source_kind="techcommunity",
        board_id="securitycopilot",
        category="AI Security",
    ),
    Source(
        id="threat_intel",
        name="Microsoft Threat Intelligence",
        url="https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/feed/",
        vendor="Microsoft",
        default_author="Microsoft",
        source_group="Official Microsoft",
        category="Threat Intelligence",
    ),
    Source(
        id="purview",
        name="Microsoft Purview",
        url="https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=microsoft-purview-blog",
        vendor="Microsoft",
        default_author="Microsoft",
        source_group="TechCommunity",
        source_kind="techcommunity",
        board_id="microsoftpurviewblog",
        category="Data Security",
    ),
    Source(
        id="ms_ai_blog",
        name="Microsoft AI Blog",
        url="https://blogs.microsoft.com/feed/",
        vendor="Microsoft",
        default_author="Microsoft",
        source_group="Official Microsoft",
        category="AI",
    ),
    Source(
        id="core_infra_security",
        name="Core Infrastructure & Security",
        url="https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=coreinfrastructureandsecurityblog",
        vendor="Microsoft",
        default_author="Microsoft",
        source_group="TechCommunity",
        source_kind="techcommunity",
        board_id="coreinfrastructureandsecurityblog",
        category="Security Operations",
    ),
    Source(
        id="network_security",
        name="Azure Network Security",
        url="https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=azurenetworksecurityblog",
        vendor="Microsoft",
        default_author="Microsoft",
        source_group="TechCommunity",
        source_kind="techcommunity",
        board_id="azurenetworksecurityblog",
        category="Network Security",
    ),
    Source(
        id="aws_security",
        name="AWS Security Bulletins",
        url="https://aws.amazon.com/security/security-bulletins/rss/feed/",
        vendor="AWS",
        default_author="Amazon Web Services",
        source_group="Official AWS",
        category="Security Advisories",
        max_entries=25,
    ),
    Source(
        id="gcp_security",
        name="Google Cloud Security Bulletins",
        url="https://docs.cloud.google.com/feeds/google-cloud-security-bulletins.xml?_gl=1%2Awukgu3%2A_ga%2AMTA3NTQxODIzOS4xNzc5NDg1Nzc4%2A_ga_WH2QY8WWF5%2AczE3Nzk0ODU3NzckbzEkZzEkdDE3Nzk0ODU3NzckajYwJGwwJGgw",
        vendor="Google Cloud",
        default_author="Google Cloud",
        source_group="Official Google Cloud",
        category="Security Advisories",
        max_entries=25,
    ),
    Source(
        id="splunk_security",
        name="Splunk Security Advisories",
        url="https://advisory.splunk.com/feed.xml",
        vendor="Splunk",
        default_author="Splunk",
        source_group="Official Splunk",
        category="Security Advisories",
        max_entries=25,
    ),
    Source(
        id="cisa_security",
        name="CISA Cybersecurity Advisories",
        url="https://www.cisa.gov/cybersecurity-advisories/all.xml",
        vendor="CISA",
        default_author="CISA",
        source_group="Official CISA",
        category="Security Advisories",
        max_entries=20,
    ),
    Source(
        id="ncsc_security",
        name="NCSC Security Feed",
        url="https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml",
        vendor="NCSC",
        default_author="NCSC",
        source_group="Official NCSC",
        category="Security Advisories",
        max_entries=15,
    ),
]


PRODUCTS: Dict[str, Dict[str, Any]] = {
    "defender-xdr": {
        "name": "Microsoft Defender XDR",
        "weight_threshold": 4,
        "patterns": [
            (r"\bmicrosoft defender xdr\b", 6),
            (r"\bdefender xdr\b", 5),
        ],
    },
    "defender-endpoint": {
        "name": "Microsoft Defender for Endpoint",
        "weight_threshold": 4,
        "patterns": [
            (r"\bmicrosoft defender for endpoint\b", 6),
            (r"\bdefender for endpoint\b", 5),
            (r"\bmde\b", 3),
        ],
    },
    "defender-identity": {
        "name": "Microsoft Defender for Identity",
        "weight_threshold": 4,
        "patterns": [
            (r"\bmicrosoft defender for identity\b", 6),
            (r"\bdefender for identity\b", 5),
            (r"\bmdi\b", 3),
        ],
    },
    "defender-cloud-apps": {
        "name": "Microsoft Defender for Cloud Apps",
        "weight_threshold": 4,
        "patterns": [
            (r"\bmicrosoft defender for cloud apps\b", 6),
            (r"\bdefender for cloud apps\b", 5),
            (r"\bmdca\b", 3),
        ],
    },
    "defender-office": {
        "name": "Microsoft Defender for Office 365",
        "weight_threshold": 4,
        "patterns": [
            (r"\bmicrosoft defender for office 365\b", 6),
            (r"\bdefender for office 365\b", 5),
        ],
    },
    "defender-cloud": {
        "name": "Microsoft Defender for Cloud",
        "weight_threshold": 4,
        "patterns": [
            (r"\bmicrosoft defender for cloud\b", 6),
            (r"\bdefender for cloud\b", 5),
        ],
    },
    "sentinel": {
        "name": "Microsoft Sentinel",
        "weight_threshold": 4,
        "patterns": [
            (r"\bmicrosoft sentinel\b", 6),
            (r"\bsentinel\b", 4),
        ],
    },
    "security-copilot": {
        "name": "Microsoft Security Copilot",
        "weight_threshold": 4,
        "patterns": [
            (r"\bmicrosoft security copilot\b", 6),
            (r"\bsecurity copilot\b", 5),
        ],
    },
    "purview": {
        "name": "Microsoft Purview",
        "weight_threshold": 3,
        "patterns": [
            (r"\bmicrosoft purview\b", 6),
            (r"\bpurview\b", 5),
        ],
    },
    "aws-security": {
        "name": "AWS Security",
        "weight_threshold": 3,
        "patterns": [
            (r"\baws\b", 4),
            (r"\bamazon web services\b", 5),
            (r"\baws security\b", 5),
        ],
    },
    "gcp-security": {
        "name": "Google Cloud Security",
        "weight_threshold": 3,
        "patterns": [
            (r"\bgoogle cloud\b", 5),
            (r"\bgcp\b", 4),
            (r"\bgoogle cloud security\b", 6),
        ],
    },
    "splunk-security": {
        "name": "Splunk Security",
        "weight_threshold": 3,
        "patterns": [
            (r"\bsplunk\b", 5),
            (r"\bsplunk advisory\b", 6),
            (r"\bsplunk security advisory\b", 7),
        ],
    },
    "cisa-advisories": {
        "name": "CISA Advisories",
        "weight_threshold": 3,
        "patterns": [
            (r"\bcisa\b", 6),
            (r"\bcisa advisory\b", 7),
            (r"\bknown exploited vulnerabilities\b", 5),
            (r"\bkev\b", 4),
        ],
    },
    "ncsc-guidance": {
        "name": "NCSC Guidance",
        "weight_threshold": 3,
        "patterns": [
            (r"\bncsc\b", 6),
            (r"\bnational cyber security centre\b", 7),
        ],
    },
    "threat-intelligence": {
        "name": "Threat Intelligence",
        "weight_threshold": 3,
        "patterns": [
            (r"\bthreat intelligence\b", 5),
            (r"\bmalware\b", 3),
            (r"\bransomware\b", 3),
            (r"\bapt\b", 3),
            (r"\bthreat actor\b", 3),
            (r"\bcampaign\b", 2),
        ],
    },
    "ai-security": {
        "name": "AI Security",
        "weight_threshold": 3,
        "patterns": [
            (r"\bai security\b", 5),
            (r"\bllm security\b", 4),
            (r"\bprompt injection\b", 4),
            (r"\bmodel poisoning\b", 4),
            (r"\bagentic\b", 2),
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


def load_previous_articles() -> List[dict]:
    if not os.path.exists(DATA_FILE):
        return []

    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("articles", [])
    except Exception:
        return []


def article_key(article: dict) -> Tuple[str, str]:
    return (
        article.get("title", "").strip(),
        article.get("link", "").strip(),
    )


def generate_diff(previous: List[dict], current: List[dict]) -> None:
    previous_map = {article_key(a): a for a in previous}
    current_map = {article_key(a): a for a in current}

    previous_keys = set(previous_map.keys())
    current_keys = set(current_map.keys())

    added = current_keys - previous_keys
    removed = previous_keys - current_keys
    unchanged = current_keys & previous_keys

    print("=" * 60)
    print("Feed Change Summary")
    print("=" * 60)
    print(f"Previous total: {len(previous)}")
    print(f"Current total : {len(current)}")
    print(f"Added         : {len(added)}")
    print(f"Removed       : {len(removed)}")
    print(f"Unchanged     : {len(unchanged)}")

    if added:
        print("\nNew articles:")

        added_articles = sorted(
            [current_map[key] for key in added],
            key=lambda x: x.get("published", ""),
            reverse=True,
        )

        for article in added_articles[:10]:
            print(f"  + {article['title']}")

    if removed:
        print("\nRemoved articles:")

        removed_articles = sorted(
            [previous_map[key] for key in removed],
            key=lambda x: x.get("published", ""),
            reverse=True,
        )

        for article in removed_articles[:10]:
            print(f"  - {article['title']}")

    print("=" * 60)


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


def deduplicate_articles(articles: List[dict]) -> Tuple[List[dict], dict]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=MAX_ARTICLE_AGE_DAYS)

    seen_links = set()
    unique = []

    duplicate_count = 0
    expired_count = 0

    for article in articles:
        link = article["link"]

        if link in seen_links:
            duplicate_count += 1
            continue

        published = datetime.fromisoformat(article["published"])

        if published < cutoff:
            expired_count += 1
            continue

        seen_links.add(link)
        unique.append(article)

    stats = {
        "raw_total": len(articles),
        "unique_total": len(unique),
        "duplicates_removed": duplicate_count,
        "expired_removed": expired_count,
    }

    return unique, stats


def generate_json_feed(articles: List[dict]) -> None:
    os.makedirs("data", exist_ok=True)

    payload = {
        "site": SITE_NAME,
        "lastUpdated": datetime.now(timezone.utc).isoformat(),
        "totalArticles": len(articles),
        "articles": articles,
    }

    with open(DATA_FILE, "w", encoding="utf-8") as f:
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

    # Apply a network timeout to every feed fetch so one slow source can't
    # stall the entire run.
    socket.setdefaulttimeout(FEED_TIMEOUT_SECONDS)

    previous_articles = load_previous_articles()
    articles = []

    for source in SOURCES:
        articles.extend(fetch_feed(source))

    articles.sort(key=lambda x: x["published"], reverse=True)

    articles, dedupe_stats = deduplicate_articles(articles)

    print("=" * 60)
    print("Deduplication Summary")
    print("=" * 60)
    print(f"Raw fetched         : {dedupe_stats['raw_total']}")
    print(f"Final unique        : {dedupe_stats['unique_total']}")
    print(f"Duplicates removed  : {dedupe_stats['duplicates_removed']}")
    print(f"Older than 30 days   : {dedupe_stats['expired_removed']}")
    print("=" * 60)

    generate_diff(previous_articles, articles)

    generate_json_feed(articles)
    generate_rss_feed(articles)

    print("=" * 60)
    print(f"Done. {len(articles)} articles generated.")
    print("=" * 60)


if __name__ == "__main__":
    main()
