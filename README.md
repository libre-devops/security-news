# 🛡️ Microsoft Security News

A daily-updated Microsoft security news aggregator hosted on GitHub Pages. Collects security-focused articles, advisories, threat intelligence, and product updates from Microsoft security sources in a clean, searchable interface.

**Live site:** [security.libredevops.org](https://security.libredevops.org)

## Features

- 📰 **Security-focused aggregation** — Microsoft security blogs, advisories, research, and product updates
- 🔍 **Search & filter** — Find articles by keyword, category, or date range
- ⭐ **Bookmarks** — Save articles for later (stored locally in your browser)
- 🌙 **Dark mode by default** — Security dashboards should be dark 😄
- 📱 **Responsive design** — Works on desktop, tablet, and mobile
- 🤖 **Auto-updated** — GitHub Actions fetches fresh content daily
- 📅 **Recent content only** — Keeps the feed lean, fast, and relevant
- 🔐 **Custom domain + HTTPS** — Hosted securely on GitHub Pages

## News Sources

| Category | Sources |
|----------|---------|
| **Official Security Blogs** | Microsoft Security Blog, Microsoft Defender Blog, Microsoft Sentinel Blog, Microsoft Entra Blog |
| **Threat Intelligence** | Microsoft Threat Intelligence, MSTIC research, Digital Defense reports |
| **Security Advisories** | Microsoft Security Response Center (MSRC), CVE advisories, release notes |
| **Identity & Access** | Entra, Conditional Access, Identity security announcements |
| **Cloud Security** | Defender for Cloud, Azure security updates, cloud posture guidance |
| **Endpoint Security** | Defender for Endpoint, attack surface reduction, endpoint detection updates |
| **Email & Collaboration Security** | Defender for Office 365, Exchange security, phishing protection updates |
| **SIEM / XDR / SOC** | Sentinel, Defender XDR, incident response guidance |
| **Compliance & Governance** | Purview security/compliance updates, governance announcements |
| **Research & Community** | Security engineering blogs, Microsoft technical security articles |

## Setup

### 1. Create the GitHub repository

```bash
gh repo create microsoft-security-news --public --source=. --remote=origin
```

### 2. Push the code

```bash
git init
git add .
git commit -m "Initial commit - Microsoft Security News"
git push -u origin master
```

### 3. Enable GitHub Pages

Go to:

**Settings → Pages**

Set:

- **Source:** Deploy from a branch *(or GitHub Actions if using workflow deployment)*
- **Branch:** `master`
- **Folder:** `/ (root)`

### 4. Configure custom domain

Set:

```text
security.libredevops.org
```

Ensure your DNS contains:

```dns
CNAME security libre-devops.github.io
```

Wait for GitHub to provision TLS and enable HTTPS.

### 5. Trigger first feed fetch

Go to:

**Actions → Fetch Microsoft Security Feeds → Run workflow**

This will generate:

```text
data/feeds.json
data/feed.xml
```

### 6. Visit your site

```text
https://security.libredevops.org
```

---

## Local Development

Install dependencies:

```bash
pip install -r scripts/requirements.txt
```

Run the feed fetcher:

```bash
python scripts/fetch_feeds.py
```

Serve locally:

```bash
python -m http.server 8000
```

Browse:

```text
http://localhost:8000
```

---

## How It Works

1. **GitHub Actions** runs daily (or manually)
2. **Python feed fetcher** pulls RSS / Atom feeds from Microsoft security sources
3. Articles are:
   - normalized
   - deduplicated
   - categorised
   - sorted by publish date
4. Results are written to:

```text
data/feeds.json
data/feed.xml
```

5. GitHub Pages publishes the updated static site
6. The frontend loads JSON dynamically and renders the live news feed

---

## Tech Stack

- **Python 3.14**
- **feedparser**
- **GitHub Actions**
- **GitHub Pages**
- **Vanilla JavaScript**
- **Progressive Web App (PWA)**
- **Service Worker caching**

---

## Roadmap

Planned improvements:

- [ ] More Microsoft security feed sources
- [ ] CVE severity filtering
- [ ] Product-based filtering (Sentinel / Defender / Entra / Purview)
- [ ] Security alert digest mode
- [ ] RSS subscription support
- [ ] Email digest generation
- [ ] Threat intelligence tagging
- [ ] Search by product/workload
- [ ] Optional vendor expansion (AWS / Google / CrowdStrike / Palo Alto)

---

## License

MIT