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

Broken/error responses are excluded from CSP coverage calculations.

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

The Page Inspector provides:

#### Overview

Review CSP findings and effective policy behavior.

#### Policy

Explore directives and sources returned by the page.

#### Recommended

View suggested CSP hardening changes based on the detected policy.

Recommendations should be reviewed and tested before being applied to production.

#### Raw Headers

Inspect the actual HTTP response headers returned by the selected page.

This makes it possible to compare headers between individual pages even when they share the same CSP policy.

---

### ⚠️ CSP Findings

CSP Lens highlights configurations that may deserve review, including examples such as:

- `script-src` containing `'unsafe-eval'`
- `style-src` containing `'unsafe-inline'`
- Missing `frame-ancestors`
- Missing or broad `form-action`
- Missing `base-uri`
- Directive fallback behavior

Findings are intended to assist manual security review rather than act as an automated vulnerability verdict.

---

### 🧭 Effective Policy

CSP Lens resolves important directive fallback behavior so you can understand what policy actually applies.

For example:

```text
object-src
↓
falls back to
↓
default-src
