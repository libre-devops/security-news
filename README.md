# 🛡️ Security News

A vendor-agnostic public cybersecurity intelligence aggregator that collects security advisories, threat intelligence, research, and product security updates into a single fast, searchable feed.

Built for security engineers, defenders, cloud architects, SOC analysts, incident responders, and anyone tired of manually checking a dozen vendor security portals every day.

**🌐 Live site:** https://security.libredevops.org
**📡 RSS feed:** https://security.libredevops.org/data/feed.xml

---

## Features

* 📰 **Multi-vendor security aggregation**
  Collects public cybersecurity content from major security vendors, advisory feeds, threat intelligence sources, and public security authorities.

* 🔍 **Fast full-text search**
  Search across:

  * article titles
  * summaries
  * vendors
  * sources
  * categories
  * threat intelligence content

* 🏷️ **Automatic categorisation**
  Dynamically classifies content into security product and intelligence categories.

* ⭐ **Bookmarks**
  Save articles locally in browser storage for later review.

* 🌙 **Theme support**
  Dark and light mode support.

* 📱 **Responsive UI**
  Optimised for desktop, tablet, and mobile.

* 📡 **RSS output**
  Consume the aggregated feed externally:

```text
https://security.libredevops.org/data/feed.xml
```

* ⚡ **Progressive Web App (PWA)**
  Installable with offline caching support.

* 🤖 **Automated updates**
  Feed ingestion and deployment runs every 6 hours.

* 📊 **Pipeline observability**
  Tracks:

  * newly added articles
  * removed articles
  * duplicate article removal
  * stale content expiry
  * feed diff summaries

* 🔐 **Security-hardened frontend**
  Includes:

  * strict Content Security Policy (CSP)
  * Referrer Policy
  * DOM-safe rendering
  * URL protocol allowlisting
  * service worker validation
  * feed sanitisation
  * defensive localStorage handling
  * same-origin cache enforcement

* 🌍 **Static hosting**
  No backend. No accounts. No cookies. No tracking.

---

## Current Source Coverage

### Microsoft

#### Core Security

* Microsoft Security Blog
* Microsoft Security Response Center (MSRC)
* Microsoft Threat Intelligence

#### Defender Ecosystem

* Microsoft Defender XDR
* Microsoft Defender for Endpoint
* Microsoft Defender for Identity
* Microsoft Defender for Office 365
* Microsoft Defender for Cloud

#### Security Operations

* Microsoft Sentinel
* Azure Network Security
* Core Infrastructure & Security

#### AI / Governance

* Microsoft Security Copilot
* Microsoft Purview
* Microsoft AI Blog

---

### Cloud Vendors

* AWS Security Bulletins
* Google Cloud Security Bulletins

---

### Security Vendors

* Splunk Security Advisories

---

### Public Security Authorities

* CISA Advisories / KEV / Alerts
* UK NCSC Guidance / Alerts

---

## Architecture

```text
Public RSS / Atom / XML Feeds
            │
            ▼
Python Feed Aggregator
            │
            ▼
Validation / Parsing
            │
            ├── Normalisation
            ├── Categorisation
            ├── Deduplication
            ├── Retention Filtering
            ├── Feed Diff Analysis
            └── RSS Regeneration
            │
            ▼
Generated Outputs
    ├── data/feeds.json
    └── data/feed.xml
            │
            ▼
GitHub Actions CI/CD
            │
            ▼
GitHub Pages Deployment
            │
            ▼
Security-Hardened Static Frontend
(Vanilla JS + CSS + HTML + PWA)
```

---

## Security Design

Although this is a static public website, it has been deliberately hardened.

### Frontend protections

Implemented protections include:

* Strict Content Security Policy
* Referrer Policy
* safe DOM rendering (`createElement`, `textContent`)
* URL protocol allowlisting (`http` / `https`)
* bookmark validation
* defensive localStorage parsing
* product/category allowlisting
* service worker cache validation
* same-origin request enforcement
* safe offline fallback behaviour

### Feed protections

Feed ingestion includes:

* external feed validation
* malformed entry rejection
* feed sanitisation
* article truncation guards
* deduplication logic
* stale content expiry
* defensive XML generation

### Privacy

This project:

* does not require accounts
* does not use cookies
* does not track visitors
* does not store personal data
* does not require authentication

---

## Local Development

### Install dependencies

```bash
pip install -r scripts/requirements.txt
```

### Generate feed data

```bash
python scripts/fetch_feeds.py
```

This generates:

```text
data/feeds.json
data/feed.xml
```

### Run locally

```bash
python -m http.server 8000
```

Browse to:

```text
http://localhost:8000
```

---

## Deployment

Deployment is automated through GitHub Actions.

### Schedule

Runs every 6 hours:

```cron
0 */6 * * *
```

### Pipeline flow

Each run:

1. Fetch public feeds
2. Validate and parse content
3. Categorise articles
4. Deduplicate overlapping entries
5. Remove stale content
6. Compare against previous state
7. Generate JSON + RSS output
8. Publish pipeline summary
9. Commit updated feed data
10. Deploy static site

---

## Technology Stack

### Backend

* Python 3.14
* feedparser
* defusedxml

### Frontend

* Vanilla JavaScript
* HTML5
* CSS3
* Progressive Web App (PWA)
* Service Workers

### Platform

* GitHub Actions
* GitHub Pages
* Custom domain + HTTPS

---

## Security Tooling

Recommended scanning:

### Python

```bash
bandit -r scripts
pip-audit
```

### Frontend

```bash
semgrep --config=auto .
```

---

## Roadmap

Potential future expansion:

### Vendors

* CrowdStrike
* Palo Alto Networks
* Cisco Talos
* Mandiant
* Elastic Security
* Tenable
* Qualys
* Rapid7

### Intelligence

* CVE enrichment
* CVSS scoring
* EPSS scoring
* exploit intelligence overlays
* vendor severity normalisation

### Features

* advanced filtering
* JSON API
* daily digest mode
* saved views
* notifications
* alert subscriptions

### Private Mode

Potential future support for authenticated feeds:

* Microsoft Message Center
* Microsoft Service Health
* tenant-specific advisory ingestion
* enterprise private feeds

---

## Inspiration / Attribution

Inspired by Ricardo Martins’ excellent Azure feed aggregator:

https://azurefeed.news

The original concept evolved into a broader public cybersecurity intelligence platform.

---

## License

MIT
