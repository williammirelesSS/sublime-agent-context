---
name: sublime-security-expert
description: >-
  Provides deep, accurate knowledge of the Sublime Security platform — MQL
  detection rules, the v0 REST API, email threat patterns (BEC, phishing,
  graymail, callback scams), hunt jobs, sender profiling, NLU classifiers,
  and link analysis. Use when the user asks about writing or reviewing MQL
  rules, querying the Sublime API, running hunt jobs, building integrations or
  automations with Sublime Security, working with a Sublime tenant, or
  detecting email threats including BEC, credential phishing, brand
  impersonation, graymail, or HTML smuggling.
---

# Sublime Security Expert

## Quick Start

1. **Read the context file** — load `sublime_expert_context.md` from the same directory. It contains the full platform reference: MDM field schema, v0 API endpoints, MQL cheat sheet, example rules, and workflow code patterns.
2. **Check for MCP tools** — if `sublime-security` MCP tools are available, use them directly to query the tenant (hunt jobs, message groups, rules, lists).
3. **Apply MQL expert notes** — when writing or reviewing rules, apply the "MQL Expert Notes" section from the context file (section 5b). It captures real gotchas and patterns beyond the syntax reference.

## Key Rules

- **v0 API only** — v1 is not customer-accessible. All endpoints are `/v0/...`
- **Ask for region first** — base URL varies by tenant. Always confirm region before constructing API requests. Options: NA-East (default), UK, EU, AU, CA, NA-West.
- **Private hunts by default** — set `private: true` on all new hunt jobs unless the user explicitly wants org-wide visibility.
- **Validate MQL before hunting** — test rules in the Sublime Rule Editor or against a known message before launching a multi-week hunt.
- **Link analysis is expensive** — always pre-filter `body.links` with a `filter()` call before passing to `ml.link_analysis()`.

## MQL Writing Checklist

When writing or reviewing an MQL rule:

- [ ] Gate on `type.inbound` (or outbound/internal) — never leave direction open
- [ ] Add `not profile.by_sender().solicited` to reduce FPs on legitimate senders
- [ ] Use `body.current_thread.text` (not `body.html.display_text`) for NLU input — avoids classifying quoted thread content
- [ ] Layer NLU with structural signals (new sender, free email provider, auth failures) — NLU alone is noisy
- [ ] Use `"outlier"` not `"rare"` for very infrequent senders — `"rare"` is not a valid prevalence value
- [ ] Check that any `$list_name` references are lists that actually exist in the tenant
- [ ] For signal layering, use the `N of (...)` pattern rather than requiring all signals

## Common Syntax Gotchas

```mql
// WRONG — ilike iterator passed incorrectly
any($org_display_names, strings.ilike(body.current_thread.text) .)

// CORRECT — iterator is the second argument
any($org_display_names, strings.ilike(body.current_thread.text, .))

// Parent scope in nested any() — use .. to reference the outer element
any(filter(attachments, .file_type == "pdf"),
    any(.scan.pdf.urls,
        not strings.icontains(..scan.exiftool.producer, .domain.domain)
    )
)
```

## Resources

| Resource | URL |
|---|---|
| MQL Message Data Model (full field schema) | `https://docs.sublime.security/reference/getmessagedatamodel-1.md` |
| API Reference Docs | `https://docs.sublimesecurity.com/reference/introduction` |
| Community Rules Repo | `https://github.com/sublime-security/sublime-rules` |
| CLI | `pip3 install sublime-cli` |

## Additional Reference

For the full platform knowledge base (MDM fields, API endpoints, all MQL functions, workflow code patterns, pagination, error handling), read:

- [sublime_expert_context.md](sublime_expert_context.md)
