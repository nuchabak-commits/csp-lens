# 🛡️ CSP Lens

**CSP Lens** is a web-based Content Security Policy analyzer that crawls a website, detects CSP headers across internal pages, groups identical policies, highlights potential security issues, and lets you inspect individual pages in detail.

Instead of checking pages one by one, enter the website homepage once and CSP Lens will crawl same-origin internal pages automatically.

> Current version: **v0.6.5 — Site Overview + Page Inspector**

---

## ✨ Features

### 🌐 Site Crawl

Enter a homepage URL and scan internal pages automatically.

- Same-origin crawling
- Configurable maximum number of pages
- URL normalization
- `<base href>` support
- Duplicate URL filtering
- Locale-loop filtering such as `/th/th/`, `/en/en/`, `/th/en/`
- Static asset filtering
- Broken-link detection
- Network/crawl error detection

CSP Lens only continues crawling links discovered from valid HTML responses.

---

### 🛡️ CSP Coverage

Get a site-wide overview of CSP implementation.

The dashboard reports:

- Scanned URLs
- Valid HTML pages
- Pages with CSP
- Pages without CSP
- Broken internal links
- Crawl errors

Broken and error responses are excluded from CSP coverage calculations.

---

### 📚 Policy Groups

Pages using identical Content Security Policies are automatically grouped together.

For each policy you can see:

- Number of pages using the policy
- Number of detected findings
- Full CSP policy
- Pages associated with the policy

Long CSP policies automatically wrap inside the interface for easier inspection.

---

### 🔎 Page Inspector

Click any scanned URL to inspect that page individually.

The Page Inspector provides four views:

#### Overview

Review CSP findings and effective policy behavior.

#### Policy

Explore directives and sources returned by the page.

#### Recommended

View suggested CSP hardening changes based on the detected policy.

Recommendations should always be reviewed and tested before being applied to production.

#### Raw Headers

Inspect the actual HTTP response headers returned by the selected page.

This makes it possible to compare headers between individual pages even when they share the same CSP policy.

---

## ⚠️ CSP Findings

CSP Lens highlights configurations that may deserve review, including examples such as:

- `script-src` containing `'unsafe-eval'`
- `style-src` containing `'unsafe-inline'`
- Missing `frame-ancestors`
- Missing or broad `form-action`
- Missing `base-uri`
- Directive fallback behavior

Findings are intended to assist manual security review rather than act as an automated vulnerability verdict.

---

## 🧭 Effective Policy

CSP Lens resolves important directive fallback behavior so you can understand what policy actually applies.

For example:

```text
object-src
↓
falls back to
↓
default-src
```

The interface distinguishes between:

- Explicit directives
- Inherited or fallback behavior
- Directives with no applicable CSP restriction

---

## 🔗 Source Summary

Sources used throughout the policy are grouped to make large CSP headers easier to understand.

Examples include:

```text
'self'
'none'
'unsafe-inline'
'unsafe-eval'
blob:
https:
https://example.com
```

You can quickly see which directives use each source.

---

## 🚦 Crawl Result Categories

CSP Lens separates crawl results into different categories.

| Category | Meaning |
| --- | --- |
| Valid Page | Successful HTML response eligible for CSP analysis |
| CSP Detected | Valid page returning a `Content-Security-Policy` header |
| No CSP | Valid HTML page without CSP |
| Broken Link | Internal URL returning `404` or `410` |
| HTTP Issue | Other unsuccessful HTTP response |
| Crawl Error | Timeout, DNS, TLS, connection, or fetch failure |

A `404` page is **not counted as a page without CSP**.

---

## 🧹 URL Filtering

The crawler automatically ignores URLs that should not normally be treated as web pages, including common assets and documents such as:

```text
.css
.js
.jpg
.png
.svg
.ico
.woff
.ttf
.pdf
.zip
.mp4
.docx
.xlsx
```

It also ignores:

```text
mailto:
tel:
javascript:
data:
#fragment
```

Only same-origin HTTP/HTTPS URLs are crawled.

The crawler also filters malformed locale loops such as:

```text
/th/th/
/en/en/
/th/en/
/en/th/
```

---

## 🏗️ Project Structure

```text
csp-lens/
├── index.html
├── styles.css
├── app.js
├── server.js
├── package.json
└── README.md
```

### Frontend

**`index.html`**

Contains the application markup and UI structure.

**`styles.css`**

Contains the application styling and responsive layout.

**`app.js`**

Handles frontend interaction, site scan results, filtering, policy groups, and Page Inspector.

### Backend

**`server.js`**

Node.js backend responsible for:

- Fetching target URLs
- Crawling internal pages
- Reading HTTP response headers
- Detecting CSP
- Normalizing URLs
- Filtering crawl targets
- Grouping CSP policies
- Returning scan results to the frontend

---

## 🚀 Getting Started

### Requirements

- Node.js
- npm

### Installation

Clone the repository:

```bash
git clone https://github.com/nuchabak-commits/csp-lens.git
cd csp-lens
```

Install dependencies:

```bash
npm install
```

Start CSP Lens:

```bash
npm start
```

Then open:

```text
http://localhost:3000
```

### Windows PowerShell

If PowerShell execution policy prevents `npm.ps1` from running, use:

```powershell
npm.cmd install
npm.cmd start
```

---

## 💡 How to Use

1. Start CSP Lens.
2. Enter the homepage URL of the website you want to inspect.
3. Select **Crawl website**.
4. Choose the maximum number of pages.
5. Click **Scan site**.
6. Review the site-wide CSP coverage.
7. Review **Policy Groups**.
8. Review broken links and crawl errors.
9. Click any scanned URL to open **Page Inspector**.
10. Inspect its policy, recommendations, findings, and raw response headers.

Example:

```text
https://example.com/
```

CSP Lens discovers same-origin internal pages and compares the CSP returned by each page.

---

## 🔐 Privacy

CSP Lens does not require target websites to install any script or plugin.

The Node.js backend requests publicly accessible pages and analyzes their HTTP response headers.

No external AI service is required for CSP analysis.

---

## ⚠️ Limitations

CSP Lens analyzes CSP primarily from HTTP response headers and crawled HTML.

It cannot always determine whether removing a CSP source will break runtime application behavior.

For example, applications may depend on:

- Dynamically generated inline styles
- Dynamically generated scripts
- Third-party widgets
- JavaScript runtime dependencies
- External form destinations
- Embedded applications

Always test recommended CSP changes before enforcing them in production.

Crawling is also limited to URLs discoverable through the pages CSP Lens visits. Pages that are not linked from the crawled site may not be discovered.

CSP Lens is designed as an analysis and review tool, not as a replacement for a full web application security assessment.

---

## 🎯 Project Goal

CSP Lens was created to make Content Security Policy review easier for developers.

The goal is to turn a long and difficult-to-read CSP header into a practical workflow:

```text
Website
   ↓
Site Crawl
   ↓
CSP Detection
   ↓
Policy Comparison
   ↓
Findings
   ↓
Page Inspection
   ↓
Recommended Changes
```

Instead of asking only:

> **Does this website have CSP?**

CSP Lens helps answer:

> **Which pages have CSP, which policy does each page use, what does the policy actually allow, and what should I review?**

---

## 🗺️ Roadmap

Potential future improvements:

- CSP differences between pages
- Export scan results
- Scan history
- Security header coverage
- Improved crawl controls
- Report-only CSP analysis
- Policy comparison
- Redirect-chain inspection

---

## 📄 License

This project is intended for development, learning, and defensive web security analysis.
