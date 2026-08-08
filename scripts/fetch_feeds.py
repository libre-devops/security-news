#!/usr/bin/env python3
"""
Security News Feed Fetcher
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess  # nosec B404
import urllib.error
import urllib.parse
import urllib.request
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

# Microsoft Graph, for the Message Center. It is the one source with no feed of
# any kind: no RSS, no Atom, no anonymous endpoint. Everything else here is a
# public feed that needs no credentials at all.
GRAPH_MESSAGE_CENTER_URL = (
    "https://graph.microsoft.com/v1.0/admin/serviceAnnouncement/messages"
)
GRAPH_RESOURCE = "https://graph.microsoft.com"
GRAPH_SCOPE = f"{GRAPH_RESOURCE}/.default"
GRAPH_PAGE_SIZE = 100

# Message Center posts are only readable in the admin centre, by someone with
# admin access to the tenant they were published to. There is no public
# permalink, so this link is a pointer for the maintainer rather than something
# a general reader can follow.
MESSAGE_CENTER_LINK = "https://admin.microsoft.com/#/MessageCenter/:/messages/"

# Post bodies travel with the article so the site can show them inline. Stored
# as PLAIN TEXT, never HTML: the front end renders everything with textContent,
# and shipping markup would hand upstream feed content a route into the DOM.
# Any links in the body are extracted separately and re-rendered as anchors
# after a scheme check.
#
# Most feeds carry far more than the card shows: the Tech Community boards and
# CISA put the whole post in <summary>, and the Microsoft blogs put it in
# <content:encoded>, all of which was previously read and thrown away.
MAX_BODY_LENGTH = 2500

# Message Center gets a longer cap because it is the only source whose link does
# not work for a reader: an admin centre permalink needs tenant admin access. If
# its body is cut short the rest is unreachable, whereas every RSS article keeps
# a working link to its full text.
MAX_MESSAGE_BODY_LENGTH = 6000

# Below this there is nothing worth expanding to, since the card already shows a
# 300 character summary. Keeps a Read More button off articles (MSRC, NCSC,
# Azure updates) whose feeds carry barely more than a headline.
MIN_BODY_LENGTH = 400

MAX_BODY_LINKS = 12

# The audience GitHub must mint its OIDC token for. It has to match the audience
# on the federated identity credential in terraform/main.tf.
ENTRA_TOKEN_AUDIENCE = "api://AzureADTokenExchange"


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

    # Category filters, matched case-insensitively against an entry's own
    # categories: the <category> elements of an RSS item, or the services a
    # Message Center post applies to. Empty include_categories means keep
    # everything; otherwise an entry must carry at least one listed category.
    # exclude_categories always wins.
    #
    # This exists because the broad Microsoft feeds are not security feeds. The
    # M365 roadmap publishes every Outlook, Teams and OneDrive change alongside
    # the handful worth showing here, so an unfiltered source would bury the
    # site. Filters run BEFORE max_entries, or the cut would starve them.
    include_categories: Tuple[str, ...] = ()
    exclude_categories: Tuple[str, ...] = ()


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
    # Roadmap and service update feeds. Both are change announcements rather
    # than security news, so both are filtered hard: the roadmap publishes over
    # 1800 items covering every Outlook, Teams and OneDrive tweak, of which only
    # a small tail is relevant here. Copilot is deliberately not on the
    # allowlist; it is the single largest category and almost none of it is
    # security. The ?filters= parameter these APIs advertise is ignored server
    # side (it returns the identical item count), so filtering has to be ours.
    Source(
        id="m365_roadmap",
        name="Microsoft 365 Roadmap",
        url="https://www.microsoft.com/releasecommunications/api/v1/m365/rss",
        vendor="Microsoft",
        default_author="Microsoft",
        source_group="Official Microsoft",
        category="Roadmap",
        max_entries=30,
        include_categories=(
            "Microsoft Defender XDR",
            "Microsoft Defender for Endpoint",
            "Microsoft Defender for Office 365",
            "Microsoft Defender for Identity",
            "Microsoft Defender for Cloud Apps",
            "Microsoft Sentinel",
            "Microsoft Purview",
            "Microsoft Entra",
            "Microsoft Intune",
        ),
    ),
    Source(
        id="azure_updates",
        name="Azure Service Updates",
        url="https://www.microsoft.com/releasecommunications/api/v2/azure/rss",
        vendor="Microsoft",
        default_author="Microsoft",
        source_group="Official Microsoft",
        category="Service Updates",
        max_entries=25,
        include_categories=(
            "Security",
            "Compliance",
            "Identity",
            "Microsoft Defender for Cloud",
            "Microsoft Sentinel",
            "Microsoft Entra ID",
            "Azure Firewall",
            "Azure Key Vault",
        ),
    ),
    # The only authenticated source. See fetch_message_center: when no token can
    # be obtained it logs and returns nothing, so a credential problem degrades
    # the site to its public feeds rather than failing the run.
    Source(
        id="message_center",
        name="Microsoft 365 Message Center",
        url=GRAPH_MESSAGE_CENTER_URL,
        vendor="Microsoft",
        default_author="Microsoft",
        source_group="Official Microsoft",
        source_kind="graph",
        category="Service Announcements",
        max_entries=40,
        include_categories=(
            "Microsoft Defender XDR",
            "Microsoft 365 Defender",
            "Microsoft Defender for Endpoint",
            "Microsoft Defender for Office 365",
            "Microsoft Defender for Identity",
            "Microsoft Defender for Cloud Apps",
            "Microsoft Sentinel",
            "Microsoft Purview",
            "Microsoft Entra",
            "Microsoft Intune",
        ),
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
    # Assigned by source rather than by text matching, so it is a reliable "this
    # came from the Message Center" marker rather than a guess. The unreachable
    # threshold keeps the classifier from ever awarding it on wording alone.
    "message-center": {
        "name": "Microsoft Message Center",
        "weight_threshold": 999,
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


def entry_body_html(entry: Any) -> str:
    """
    The richest markup an entry offers. content:encoded when the feed populates
    it (the Microsoft blogs put the whole article there), otherwise the summary,
    which for the Tech Community boards and CISA is already the entire post.
    """
    content = entry.get("content")

    if isinstance(content, list) and content and content[0].get("value"):
        return content[0]["value"]

    return entry.get("summary", "") or ""


def normalize_entry(entry: Any, source: Source) -> Optional[dict]:
    title = clean_html(entry.get("title", "Untitled"))
    summary_raw = clean_html(entry.get("summary", ""))

    if source.id == "msrc" and re.match(r"^CVE-\d{4}-\d+", title, re.IGNORECASE):
        return None

    summary = truncate(summary_raw)
    products = classify_products(title, summary_raw, source.name)

    body_html = entry_body_html(entry)
    body_text = clean_html(body_html)

    article = {
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

    # Only attach a body when it genuinely adds to the summary already on the
    # card, so Read More never opens to the same text the reader just read.
    if len(body_text) >= MIN_BODY_LENGTH:
        article["body"] = truncate(body_text, MAX_BODY_LENGTH)
        article["links"] = extract_links(body_html)

    return article


def entry_categories(entry: Any) -> List[str]:
    """The <category> terms on a feed entry, as plain strings."""
    return [
        (tag.get("term") or "").strip()
        for tag in (entry.get("tags") or [])
        if (tag.get("term") or "").strip()
    ]


def passes_category_filter(source: Source, categories: List[str]) -> bool:
    """Whether an entry's own categories satisfy the source's filters."""
    if not source.include_categories and not source.exclude_categories:
        return True

    lowered = {category.lower() for category in categories}

    if any(excluded.lower() in lowered for excluded in source.exclude_categories):
        return False

    if not source.include_categories:
        return True

    return any(included.lower() in lowered for included in source.include_categories)


def fetch_feed(source: Source) -> List[dict]:
    print(f"Fetching: {source.name}")

    try:
        feed = feedparser.parse(source.url)
        articles = []
        filtered_out = 0

        # Filter first, slice second. Doing it the other way round would cut the
        # newest max_entries items and then filter what survived, so a broad
        # feed like the roadmap would usually yield nothing at all.
        for entry in feed.entries:
            if not passes_category_filter(source, entry_categories(entry)):
                filtered_out += 1
                continue

            article = normalize_entry(entry, source)
            if article:
                articles.append(article)

            if len(articles) >= source.max_entries:
                break

        print(f"  Found {len(articles)} articles")
        print(f"  Feed contains {len(feed.entries)} raw entries")
        if filtered_out:
            print(f"  Filtered out {filtered_out} entries by category")
        return articles

    except Exception as ex:
        print(f"  Error fetching {source.name}: {ex}")
        return []


def http_json(
    url: str,
    *,
    data: Optional[bytes] = None,
    headers: Optional[Dict[str, str]] = None,
) -> dict:
    """A small JSON HTTP helper, so the Graph path needs no extra dependency."""
    request = urllib.request.Request(  # nosec B310
        url,
        data=data,
        headers=headers or {},
        method="POST" if data else "GET",
    )

    if not url.lower().startswith("https://"):
        raise ValueError(f"Refusing to call a non-HTTPS URL: {url}")

    with urllib.request.urlopen(  # nosec B310
        request, timeout=FEED_TIMEOUT_SECONDS
    ) as response:
        return json.load(response)


def github_oidc_token() -> Optional[str]:
    """The GitHub Actions OIDC token, when running inside Actions."""
    request_url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    request_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")

    if not request_url or not request_token:
        return None

    url = f"{request_url}&audience={urllib.parse.quote(ENTRA_TOKEN_AUDIENCE)}"

    payload = http_json(url, headers={"Authorization": f"Bearer {request_token}"})
    return payload.get("value")


def entra_token_from_github_oidc() -> Optional[str]:
    """
    Exchange the GitHub OIDC token for a Graph token, the client credentials
    flow with a client assertion. No client secret is involved: the assertion IS
    the credential, and it is minted per job and expires in minutes.
    """
    client_id = os.environ.get("MESSAGE_CENTER_CLIENT_ID")
    tenant_id = os.environ.get("MESSAGE_CENTER_TENANT_ID")

    if not client_id or not tenant_id:
        return None

    assertion = github_oidc_token()
    if not assertion:
        return None

    body = urllib.parse.urlencode(
        {
            "client_id": client_id,
            "scope": GRAPH_SCOPE,
            "grant_type": "client_credentials",
            "client_assertion_type": (
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            ),
            "client_assertion": assertion,
        }
    ).encode()

    payload = http_json(
        f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    return payload.get("access_token")


def entra_token_from_azure_cli() -> Optional[str]:
    """
    Local development fallback: borrow the signed-in user's Graph token from the
    Azure CLI, so `just feeds` works on a laptop after `az login` without any
    app registration involvement.
    """
    try:
        result = subprocess.run(  # nosec B603 B607
            [
                "az",
                "account",
                "get-access-token",
                "--resource",
                GRAPH_RESOURCE,
                "--output",
                "json",
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    if result.returncode != 0:
        return None

    try:
        return json.loads(result.stdout).get("accessToken")
    except json.JSONDecodeError:
        return None


def graph_access_token() -> Optional[str]:
    """
    A Graph token, by whichever route is available. Returns None rather than
    raising: the Message Center is one source among many, so losing it should
    cost the site that section, not the whole run.
    """
    explicit = os.environ.get("MESSAGE_CENTER_ACCESS_TOKEN")
    if explicit:
        print("  Using MESSAGE_CENTER_ACCESS_TOKEN from the environment")
        return explicit

    try:
        federated = entra_token_from_github_oidc()
        if federated:
            print("  Authenticated by GitHub Actions federated identity")
            return federated
    except (urllib.error.URLError, ValueError, KeyError) as ex:
        print(f"  Federated identity exchange failed: {ex}")

    cli = entra_token_from_azure_cli()
    if cli:
        print("  Authenticated by the Azure CLI (local development)")
        return cli

    return None


def parse_graph_datetime(value: str) -> str:
    """
    Graph timestamps to the isoformat the rest of the pipeline expects.
    Graph emits up to seven fractional-second digits, which fromisoformat
    rejects (it accepts three or six), so they are trimmed before parsing.
    """
    text = (value or "").strip().replace("Z", "+00:00")
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return datetime.now(timezone.utc).isoformat()

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.isoformat()


def extract_links(html: str) -> List[dict]:
    """
    Pull the anchors out of a Message Center body so they survive the strip to
    plain text. Only http(s) is kept, and the label is stripped of markup, so
    what reaches the front end is a plain label and a scheme-checked URL.
    """
    links: List[dict] = []
    seen = set()

    for href, label in re.findall(
        r"<a\s[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>",
        html or "",
        re.IGNORECASE | re.DOTALL,
    ):
        url = unescape(href).strip()

        if not url.lower().startswith(("http://", "https://")) or url in seen:
            continue

        seen.add(url)
        text = clean_html(label) or url
        links.append({"label": truncate(text, 120), "url": url})

        if len(links) >= MAX_BODY_LINKS:
            break

    return links


def normalize_message(message: dict, source: Source) -> Optional[dict]:
    """Turn one Graph serviceAnnouncement message into an article."""
    message_id = (message.get("id") or "").strip()
    title = clean_html(message.get("title") or "Untitled")

    if not message_id:
        return None

    body = (message.get("body") or {}).get("content") or ""
    summary_raw = clean_html(body)
    services = [service for service in (message.get("services") or []) if service]

    published = parse_graph_datetime(
        message.get("lastModifiedDateTime") or message.get("startDateTime") or ""
    )

    # The services a post applies to are the strongest classification signal it
    # carries, so they are fed to the classifier alongside the body text. The
    # Message Center marker is then prepended by hand: it is a fact about where
    # the post came from, not something to infer from its wording.
    products = classify_products(
        title, f"{summary_raw} {' '.join(services)}", source.name
    )
    products = [
        {
            "id": "message-center",
            "name": PRODUCTS["message-center"]["name"],
            "score": 10,
        }
    ] + [product for product in products if product["id"] != "general-security"]

    return {
        "title": title,
        "link": f"{MESSAGE_CENTER_LINK}{message_id}",
        "published": published,
        "summary": truncate(summary_raw),
        "author": source.default_author,
        "source": source.name,
        "source_id": source.id,
        "source_group": source.source_group,
        "source_kind": source.source_kind,
        "vendor": source.vendor,
        "source_category": source.category,
        "board_id": source.board_id,
        "message_id": message_id,
        "services": services,
        # The whole post as plain text, so the site can show it inline rather
        # than sending readers to an admin centre they cannot open.
        "body": truncate(summary_raw, MAX_MESSAGE_BODY_LENGTH),
        "links": extract_links(body),
        "products": products,
        "tags": [product["name"] for product in products],
    }


def fetch_message_center(source: Source) -> List[dict]:
    """
    Message Center, over Graph. Unlike every other source this one is
    authenticated and tenant scoped, so it is also the only one that can fail
    for reasons that have nothing to do with the network.
    """
    print(f"Fetching: {source.name}")

    token = graph_access_token()
    if not token:
        print("  No Graph token available, skipping the Message Center.")
        print("  Locally: az login. In Actions: set the MESSAGE_CENTER_* variables.")
        return []

    since = (
        datetime.now(timezone.utc) - timedelta(days=MAX_ARTICLE_AGE_DAYS)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    query = urllib.parse.urlencode(
        {
            "$filter": f"lastModifiedDateTime ge {since}",
            "$top": str(GRAPH_PAGE_SIZE),
            "$orderby": "lastModifiedDateTime desc",
        }
    )

    try:
        payload = http_json(
            f"{source.url}?{query}",
            headers={"Authorization": f"Bearer {token}"},
        )
    except urllib.error.HTTPError as ex:
        detail = (
            "forbidden: has ServiceMessage.Read.All been consented?"
            if ex.code == 403
            else ex.reason
        )
        print(f"  Error fetching {source.name}: HTTP {ex.code} ({detail})")
        return []
    except (urllib.error.URLError, ValueError) as ex:
        print(f"  Error fetching {source.name}: {ex}")
        return []

    messages = payload.get("value") or []
    articles = []
    filtered_out = 0

    for message in messages:
        if not passes_category_filter(source, message.get("services") or []):
            filtered_out += 1
            continue

        article = normalize_message(message, source)
        if article:
            articles.append(article)

        if len(articles) >= source.max_entries:
            break

    print(f"  Found {len(articles)} articles")
    print(f"  Message Center returned {len(messages)} raw messages")
    if filtered_out:
        print(f"  Filtered out {filtered_out} messages by service")

    return articles


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
        if source.source_kind == "graph":
            articles.extend(fetch_message_center(source))
        else:
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
