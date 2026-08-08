# Security Policy

## Supported Versions

<<<<<<< docs/security-policy
Only the currently deployed site, built from `master` and published to
https://security.libredevops.org, receives security updates.

Tags in this repository are historical markers rather than supported releases.
There is no backport process: fixes land on `master` and reach the live site on
the next deployment.

## Scope

Security News is a static site with no backend, no accounts and no server-side
request handling. Feeds are ingested by a scheduled GitHub Actions run and the
result is published to GitHub Pages.

In scope:

- The feed ingestion script (`scripts/fetch_feeds.py`) and its dependencies
  (`scripts/requirements.txt`).
- The front end: `index.html`, `js/`, `css/`, and the service worker (`sw.js`).
- The generated artefacts in `data/` (`feeds.json`, `feed.xml`), including
  injection or escaping issues arising from untrusted upstream feed content.
- The workflows in `.github/workflows/`, including their permissions and any
  path allowing an untrusted input to influence a commit or deployment.
- The deployed site and feed at https://security.libredevops.org.

Out of scope:

- The content of aggregated articles and the upstream vendor feeds themselves.
  Report those to the originating vendor — this project only republishes them.
- Inaccurate, missing, stale or miscategorised articles. These are correctness
  bugs, not vulnerabilities; raise a normal issue.
- Vulnerabilities in third-party dependencies that already carry a public
  advisory. Dependabot tracks those automatically, so a report adds nothing.

Because this project aggregates security content, a plausible finding is one
where hostile upstream feed content reaches a viewer's browser or influences the
build — stored XSS through an article title or summary, HTML or XML injection
into `feed.xml`, service worker cache poisoning, or a workflow that can be
steered by feed data.

## Reporting a Vulnerability

Report privately using GitHub's private vulnerability reporting:

**https://github.com/libre-devops/security-news/security/advisories/new**

Do **not** open a public issue for an undisclosed vulnerability.

Please include:

- The affected component and, where relevant, the commit or deployment date.
- Reproduction steps, ideally with the specific feed entry or payload involved.
- The impact you believe it has.
- Any suggested remediation, if you have one.

## What to Expect

- Acknowledgement of receipt within **3 business days**.
- An initial triage decision within **7 business days**.

If the report is accepted, we will develop a fix and coordinate disclosure
timing with you once a patch or mitigation is deployed. If it is declined, we
will tell you why — for example not reproducible, out of scope as described
above, or already publicly known.

Please hold off on public disclosure until remediation is complete. This is a
volunteer-maintained project, so please be reasonable about timelines.

Published advisories:
**https://github.com/libre-devops/security-news/security/advisories**
