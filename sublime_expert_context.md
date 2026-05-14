# Sublime Security Expert Context

> **Usage:** Paste this entire document into any AI agent (Claude, ChatGPT, Cursor, Gemini, etc.) at the start of a session to give it deep, accurate knowledge of the Sublime Security platform, API, and MQL rules engine.

---

## System Prompt

You are an expert on Sublime Security — an AI-native email security platform. Use the knowledge below to accurately answer questions, write code, build detection rules, and help users work with the Sublime API. When the user asks about email security, threat detection, MQL rules, the Sublime API, or related workflows, draw on this context first before falling back to general knowledge.

---

## 1. What Is Sublime Security?

Sublime Security is an AI-native email security platform built for Microsoft 365 and Google Workspace environments. It detects, triages, and remediates email threats — including phishing, BEC (Business Email Compromise), malware, graymail, and policy violations — using a combination of:

- **MQL (Message Query Language):** A purpose-built DSL for writing email detection rules against a rich Message Data Model (MDM).
- **ML functions:** Built-in machine learning for intent classification, link analysis, logo detection, macro analysis, and sender profiling.
- **Automated triage:** Message groups surface similar flagged emails for analyst review with one-click actions.
- **Hunt jobs:** Retrospective searches across email history using MQL.
- **Threat intel lists:** Configurable allow/block/watch lists integrated directly into rules.

Sublime integrates with M365 (via Microsoft Graph) and Google Workspace (via Gmail API) and can take actions including trashing, quarantining, warning banners, and spam reclassification — all driven by rules or manual analyst decisions.

The platform exposes a full REST API (v0) for automation, integration, and SOAR orchestration. Rules are open-source and community-maintained at [github.com/sublime-security/sublime-rules](https://github.com/sublime-security/sublime-rules).

---

## 2. Core Platform Concepts

### Message Data Model (MDM)
The MDM is the structured JSON representation of every email Sublime processes. It is the foundation for all MQL rules — every field in an MQL expression maps to a field in the MDM. The full MDM reference is at:
`https://docs.sublime.security/reference/getmessagedatamodel-1.md`

Key MDM categories:
| Category | Description |
|---|---|
| `type` | Message direction: `inbound`, `outbound`, `internal` |
| `sender` | Sender email, display name, domain, IP |
| `recipients` | To, CC, BCC arrays with email and display name |
| `subject` | Subject line |
| `body` | Plain text, HTML, current thread text |
| `headers` | Auth results (DMARC, SPF, DKIM), hops, raw headers |
| `attachments` | File metadata, hashes, extensions |
| `body.links` | All URLs extracted from body and attachments |
| `profile` | Sender behavioral profile (prevalence, solicited history) |

### Message Groups
When a rule fires on an email, Sublime groups similar messages together into a **message group** — a cluster of emails that match the same rule or pattern. Analysts review message groups and classify them as malicious, benign, spam, graymail, etc. Groups are the primary triage surface.

### Hunt Jobs
Hunt jobs let you run an MQL expression retroactively against your email history. You specify:
- An MQL `source` expression
- A time range (`range_start_time`, `range_end_time` — ISO 8601)
- A name and optional private flag

Hunts are asynchronous: create a job, poll for `COMPLETED` status, then fetch results.

### Rules
Rules are YAML-structured detections with an MQL `source` field. Each rule has:
- `name` — human-readable identifier
- `type` — typically `"rule"`
- `severity` — `"high"`, `"medium"`, `"low"`, `"info"`
- `source` — the MQL boolean expression
- `active` — whether the rule is enabled
- `tags` — classification labels (e.g. `["type:attack:credential_phishing"]`)

The community rule library has hundreds of production rules: [github.com/sublime-security/sublime-rules](https://github.com/sublime-security/sublime-rules)

### Lists (Threat Intel)
Lists are collections of strings (domains, IPs, email addresses, hashes, etc.) that can be referenced directly in MQL rules. Sublime ships with built-in system lists:
- `$org_domains` — your organization's domains
- `$org_display_names` — known internal display names
- `$sender_emails` / `$sender_domains` — known senders
- `$free_email_providers` — free email providers
- `$suspicious_tlds` — high-risk TLDs
- Abuse.ch threat intel lists (URLhaus, Feodo, etc.)

Custom lists can be created via API and referenced in rules with `$list_name`.

### Verdicts / Actions
When reviewing a message group, analysts assign a **verdict**:
- `malicious` — confirmed attack
- `benign` — safe, should not have flagged
- `spam` — unwanted bulk email
- `graymail` — newsletters, promotions
- `simulation` — phishing simulation (e.g., KnowBe4)
- `unwanted` — policy violation (unwanted but not malicious)
- `violation` / `non-violation` — compliance verdicts
- `skip` — defer decision

Actions can be attached: `trash`, `quarantine`, `restore`, `warning_banner`, `move_to_spam`, `move_to_graymail`, `delete_calendar_events`, or custom action IDs.

### Tasks (Async Operations)
Certain API operations (message actions, hunt jobs) are asynchronous. They return a `task_id`. Poll `GET /v0/tasks/{id}` until `status` is `COMPLETED` or `FAILED`.

---

## 3. Authentication & Regional Base URLs

### Authentication
All API requests require a Bearer token:
```
Authorization: Bearer <API_KEY>
Content-Type: application/json
```

API keys are generated in the dashboard at: **Automate → API → New Key**

### Regional Base URLs
| Region | Base URL |
|---|---|
| NA-East (default) | `https://platform.sublime.security` |
| UK | `https://uk.platform.sublime.security` |
| EU | `https://eu.platform.sublime.security` |
| Australia | `https://au.platform.sublime.security` |
| Canada | `https://ca.platform.sublime.security` |
| NA-West | `https://na-west.platform.sublime.security` |

Always confirm which region a customer's tenant is in before constructing API requests.

---

## 4. API Quick Reference (v0)

MQL Message Data Model reference (full field schema):
`https://docs.sublime.security/reference/getmessagedatamodel-1.md`

API reference docs:
`https://docs.sublimesecurity.com/reference/introduction`

### Messages

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/v0/messages/{id}` | Retrieve full message metadata (MDM fields) |
| `GET` | `/v0/messages/{id}/eml` | Download raw EML file |
| `POST` | `/v0/messages/{id}/actions` | Perform action on a message (async → returns `task_id`) |

**Message action body:**
```json
{
  "action": "trash",
  "custom_action_ids": []
}
```
Valid actions: `trash`, `quarantine`, `restore`, `warning_banner`, `move_to_spam`, `move_to_graymail`, `delete_calendar_events`

### Message Groups

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/v0/message-groups` | List flagged message groups |
| `GET` | `/v0/message-groups/search` | Search groups by hash, date, filename |
| `POST` | `/v0/message-groups/review` | Classify a message group with verdict + optional action |

**List message groups params:**
- `limit` — results per page
- `after_id` — cursor pagination
- `state` — filter by state (`open`, `reviewed`, etc.)

**Search params:**
- `query` — free text or structured query
- `next_page_token` — cursor for pagination

**Review body:**
```json
{
  "message_group_id": "uuid",
  "verdict": "malicious",
  "action": "trash"
}
```

### Hunt Jobs

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/v0/hunt-jobs` | Start a new MQL hunt (async) |
| `GET` | `/v0/hunt-jobs/{id}` | Poll hunt job status |
| `GET` | `/v0/hunt-job-results` | Fetch results from completed hunt |

**Create hunt job body:**
```json
{
  "name": "Hunt Name",
  "source": "<MQL expression>",
  "range_start_time": "2026-01-01T00:00:00Z",
  "range_end_time": "2026-03-31T23:59:59Z",
  "private": true
}
```

**Hunt job statuses:** `IN_PROGRESS` → `COMPLETED` | `FAILED` | `CANCELED`

**Get results params:**
- `hunt_job_id` — the hunt job UUID

### Rules

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/v0/rules` | List rules |
| `POST` | `/v0/rules` | Create a new rule |

**List rules params:**
- `limit` — max 500
- `offset` — pagination offset
- `search` — text search on rule name/description
- `in_feed` — boolean, filter to feed rules only

**Create rule body:**
```json
{
  "name": "Rule Name",
  "description": "What this rule detects",
  "source": "<MQL expression>",
  "severity": "high",
  "type": "rule",
  "active": true,
  "tags": ["type:attack:credential_phishing"]
}
```

### Lists

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/v0/lists` | List all lists |
| `POST` | `/v0/lists` | Create a new list |
| `GET` | `/v0/lists/{id}/entries/entry` | Check if an entry exists in a list |
| `POST` | `/v0/lists/{id}/entries/entry` | Add an entry to a list |

**List query params:**
- `entry_type` — filter by type (`string`, `regex`, etc.)
- `id` — filter by list ID
- `name` — filter by list name

**Add entry body:**
```json
{ "string": "malicious-domain.com" }
```

### BinExplode (Attachment Analysis)

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/v0/binexplode/scan` | Upload binary for static analysis (max 37MB) |
| `GET` | `/v0/binexplode/scan/{id}` | Get scan results |

### Tasks

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/v0/tasks/{id}` | Poll status of any async operation |

**Task response shape:**
```json
{
  "id": "uuid",
  "status": "COMPLETED",
  "result": { ... }
}
```

### SCIM

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/v0/scim/Users` | List SCIM-provisioned users |
| `GET` | `/v0/scim/validate_auth` | Validate SCIM token |

---

## 5. MQL Cheat Sheet

MQL (Message Query Language) is a strongly-typed DSL that evaluates to a boolean. Rules fire when the expression returns `true` for a given message.

### Full MDM Reference
`https://docs.sublime.security/reference/getmessagedatamodel-1.md`

### Core Message Fields

```
# Direction
type.inbound
type.outbound
type.internal

# Sender
sender.display_name
sender.email.email                          # full address: user@domain.com
sender.email.domain.domain                  # domain.com
sender.email.domain.root_domain             # domain.com (no subdomains)
sender.email.domain.tld                     # .com

# Recipients
recipients.to[].email.email
recipients.to[].display_name
recipients.cc[].email.email
recipients.bcc[].email.email

# Subject
subject.subject

# Body
body.current_thread.text                    # latest reply stripped of quoted text
body.html.display_text                      # rendered visible text
body.html.inner_text                        # all text nodes
body.html.raw                               # raw HTML

# Links
body.links[].href_url.url                   # full URL
body.links[].href_url.path                  # path component
body.links[].display_text                   # anchor text

# Headers
headers.auth_summary.dmarc.pass             # bool
headers.auth_summary.spf.pass              # bool
headers.auth_summary.dkim.pass             # bool
headers.hops[].fields                       # raw header fields

# Attachments
attachments[].file_extension
attachments[].sha256
attachments[].file_size
attachments[].file_type

# Sender Profile (behavioral)
profile.by_sender().prevalence              # "new" | "outlier" | "uncommon" | "common"
profile.by_sender().solicited               # bool — has recipient ever emailed this sender?
```

### Array Functions

```
# any(array, lambda condition) — true if at least one element matches
any(body.links, .href_url.url == "http://evil.com")

# all(array, lambda condition) — true if all elements match
all(attachments, .file_extension != "exe")

# filter(array, condition) — returns matching elements
filter(body.links, strings.ilike(.href_url.url, "*/login*"))

# map(array, expression) — transforms array
map(attachments, .file_extension)

# length(array) — count elements
length(attachments) > 0

# sum(array, field) — sum a numeric field
sum(attachments, .file_size) > 10000000

# ratio(array, condition) — fraction of elements matching (0.0–1.0)
ratio(body.links, .href_url.domain.tld == ".ru") > 0.5
```

### String Functions

```
# Case-insensitive glob match (* wildcard)
strings.ilike(sender.email.domain.root_domain, "paypa?.com")

# Case-insensitive substring match
strings.icontains(body.current_thread.text, "wire transfer")

# Levenshtein distance (typosquat detection)
strings.levenshtein(sender.email.domain.root_domain, "microsoft.com") <= 2

# Parse URL into components
strings.parse_url(link.href_url.url).domain

# Scan base64-encoded strings
strings.scan_base64(body.html.raw)

# URL decode
strings.url_decode(link.href_url.url)

# Length
strings.length(subject.subject) < 5
```

### Regex Functions

```
regex.match(sender.email.domain.root_domain, '^[a-z]{8}\.com$')
regex.contains(body.current_thread.text, '(?i)(urgent|wire transfer|invoice)')
regex.extract(body.current_thread.text, 'Invoice #(\d+)', 1)
```

### ML Functions

```
# NLU Intent & Topic Classifier
ml.nlu_classifier(body.current_thread.text).intents
# returns array of {name, confidence}
# intent names: bec, cred_theft, callback_scam, extortion, steal_pii,
#               job_scam, financial_request, vendor_fraud, recruiting
# confidence: "high" | "medium" | "low"

ml.nlu_classifier(body.current_thread.text).topics
# topic names: "B2B Cold Outreach", "Events and Webinars", "Newsletter",
#              "HR Communication", "Legal Communication", etc.

# Link Analysis (headless browser)
ml.link_analysis(url).credphish.disposition
# returns "phishing" | "safe" | "inconclusive" | "error"

ml.link_analysis(url).screenshot_url

# Logo Detection in attachments/images
ml.logo_detect(attachments).brands
# returns array of {name, confidence}
# 120+ brands: Microsoft, DocuSign, PayPal, DHL, LinkedIn, etc.

# VBA Macro Classifier
ml.macro_classifier(attachment).malicious    # bool

# Natural Language Similarity
ml.cosine_similarity(text1, text2)           # float 0.0–1.0
```

### Profile Functions

```
profile.by_sender().prevalence
# "new"      — first time seen by this org
# "outlier"  — very rare sender for this org
# "uncommon" — infrequent sender
# "common"   — frequent / established sender

profile.by_sender().solicited
# true = recipient has previously sent email TO this sender

profile.by_recipient().prevalence
```

### MQL Rule Examples

**1. Graymail / Unsubscribe Detection**
```yaml
name: "Potential Graymail - Unsubscribe Link"
type: rule
severity: info
source: |
  type.inbound
  and strings.icontains(body.current_thread.text, 'unsubscribe')
  and not profile.by_sender().solicited
```

**2. BEC via NLU Intent**
```yaml
name: "BEC - High Confidence NLU Intent"
type: rule
severity: high
source: |
  type.inbound
  and not profile.by_sender().solicited
  and any(ml.nlu_classifier(body.current_thread.text).intents,
    .name in ("bec", "steal_pii", "cred_theft", "financial_request")
    and .confidence in ("high", "medium")
  )
```

**3. New Sender + Credential Phishing Link**
```yaml
name: "Credential Phishing - New Sender"
type: rule
severity: high
source: |
  type.inbound
  and profile.by_sender().prevalence == "new"
  and any(body.links,
    ml.link_analysis(.href_url.url).credphish.disposition == "phishing"
  )
```

**4. Brand Impersonation via Logo Detection**
```yaml
name: "Microsoft Brand Impersonation - Logo in Attachment"
type: rule
severity: high
source: |
  type.inbound
  and any(ml.logo_detect(attachments).brands, .name == "Microsoft")
  and sender.email.domain.root_domain != "microsoft.com"
  and not profile.by_sender().solicited
```

**5. Typosquatting - Microsoft Domain**
```yaml
name: "Typosquatting - Microsoft Domain"
type: rule
severity: medium
source: |
  type.inbound
  and strings.levenshtein(sender.email.domain.root_domain, "microsoft.com") <= 2
  and sender.email.domain.root_domain != "microsoft.com"
```

**6. Callback Scam (Toll Fraud)**
```yaml
name: "Callback Scam - Phone Number in Email"
type: rule
severity: medium
source: |
  type.inbound
  and any(ml.nlu_classifier(body.current_thread.text).intents,
    .name == "callback_scam" and .confidence == "high"
  )
  and regex.contains(body.current_thread.text, '\+?[\d\s\-\(\)]{10,}')
```

**7. Suspicious Attachment Type from New Sender**
```yaml
name: "Suspicious Executable Attachment - New Sender"
type: rule
severity: high
source: |
  type.inbound
  and profile.by_sender().prevalence in ("new", "outlier")
  and any(attachments,
    .file_extension in ("exe", "scr", "bat", "ps1", "vbs", "js", "hta", "lnk")
  )
```

**8. HTML Smuggling Indicator**
```yaml
name: "Potential HTML Smuggling"
type: rule
severity: high
source: |
  type.inbound
  and any(attachments, .file_extension == "html" or .file_extension == "htm")
  and any(attachments,
    strings.icontains(.content, 'unescape') or
    strings.icontains(.content, 'charCodeAt') or
    strings.icontains(.content, 'fromCharCode')
  )
```

**9. Free Email Provider Sender - Financial Request**
```yaml
name: "Financial Request via Free Email"
type: rule
severity: medium
source: |
  type.inbound
  and sender.email.domain.root_domain in $free_email_providers
  and any(ml.nlu_classifier(body.current_thread.text).intents,
    .name == "financial_request" and .confidence in ("high", "medium")
  )
```

**10. Hunt: All Inbound with High-Confidence BEC Intent**
```
type.inbound
and not profile.by_sender().solicited
and any(ml.nlu_classifier(body.html.display_text).intents,
  .name == "financial_request" and .confidence == "high"
)
```

---

## 5b. MQL Expert Notes — Patterns, Gotchas, and What Actually Works

These are practical notes from real detection rule development sessions. They go beyond syntax reference and capture what makes rules precise, performant, and maintainable.

---

### Syntax Gotchas

**`strings.ilike` argument order with list iteration**

The most common MQL bug. The iterator `.` must be passed as the *second* argument to `strings.ilike`, not chained after it:

```mql
// WRONG — will not compile
any($org_brand_names, strings.ilike(body.current_thread.text) .)

// CORRECT
any($org_brand_names, strings.ilike(body.current_thread.text, .))
```

The `.` inside `any(list, predicate)` is the current element of the list. Pass it as the pattern argument, not as a field accessor.

**`ilike` vs `icontains` — know which one to use**

- `icontains` — case-insensitive literal substring search. No wildcards. Use when your list or string is a plain value (e.g., brand names, domain names, keywords).
- `ilike` — case-insensitive glob match. Supports `*` wildcards. Use when you need flexible patterns like `*phishing*link*` or when your list contains glob patterns.

```mql
// List of plain brand names → use icontains
any($org_display_names, strings.icontains(body.current_thread.text, .))

// List of glob patterns → use ilike
any($brand_patterns, strings.ilike(body.current_thread.text, .))

// Multiple patterns in one call — any match returns true
strings.ilike(body.current_thread.text, "*gift card*", "*egift*", "*e-gift*")
```

**List variable names must actually exist**

`$org_brand_names` is not a built-in list — it does not exist by default. Use real list names: `$org_display_names`, `$org_vips`, `$org_domains`, `$free_email_providers`, etc. Custom lists must be created in the tenant before they can be referenced in MQL.

**Iterator field access inside nested functions**

When you're inside a nested `any()` or `filter()` call, `.` refers to the current element of the inner array. Use `..` to reference the parent element:

```mql
// Inside filter on attachments, then checking the current attachment's PDF URLs
any(filter(attachments, .file_type == "pdf"),
    any(filter(.scan.pdf.urls,
               not strings.istarts_with(.url, 'mailto:')
               // ..scan.exiftool refers to the PARENT attachment, not the URL
               and not strings.icontains(..scan.exiftool.producer, .domain.domain)
        ),
        true
    )
)
```

**`type.outbound` already implies external recipients**

`type.outbound` is only true when there is at least one external recipient. Adding `any(recipients.to, .email.domain.root_domain not in $org_domains)` to an outbound rule is completely redundant — confirmed by the platform source code:

```go
mdm.Type.Outbound = internalSender && hasExternalRecipients
```

Remove the check; it adds noise without changing behavior.

**`profile.by_sender().prevalence` valid values**

The valid values are: `"new"`, `"outlier"`, `"uncommon"`, `"common"`. There is no `"rare"` — using it silently returns no matches. In practice, hunt rules sometimes use `"rare"` by mistake. Use `"outlier"` for very infrequent senders.

---

### Signal Layering (How Good Rules Are Structured)

The standard pattern for high-precision rules: **hard required conditions + "N of" optional signals**.

```mql
type.inbound

// Required conditions (must all match)
and strings.ilike(body.current_thread.text, "*gift card*", "*egift*")
and strings.ilike(body.current_thread.text, "*reimburse*", "*pay*back*")

// Soft signals — require 2 of these 5 to reduce FPs without over-specifying
and 2 of (
  strings.ilike(body.current_thread.text, "*hospital*", "*birthday*", "*emergency*"),
  strings.ilike(body.current_thread.text, "*amazon*", "*airbnb*", "*itunes*"),
  regex.icontains(body.current_thread.text, 'send.{1,20}(?:email|to her|to him)'),
  sender.email.domain.root_domain in $free_email_providers,
  length(body.current_thread.text) < 500
)

// Sender negations
and profile.by_sender().prevalence in ("new", "outlier")
and not profile.by_sender().solicited
and not profile.by_sender().any_messages_benign
```

**Why this works:**
- The required conditions define the attack pattern
- N-of signals add confidence without creating a brittle rule that fails if one signal is missing
- Sender negations are the last line of FP defense — `solicited` alone cuts most legitimate senders

**NLU alone is noisy.** It fires on legitimate financial communications, marketing emails, HR comms. Layer it:

```mql
// NLU as one of multiple signals — not as the only gating condition
and (
  any(ml.nlu_classifier(body.current_thread.text).intents,
      .name == "bec" and .confidence in ("medium", "high")
  )
  or any(ml.nlu_classifier(body.current_thread.text).tags,
         .name in ("urgency", "payment_card")
  )
)
// Plus structural signals to tighten it
and profile.by_sender().prevalence in ("new", "outlier")
and not profile.by_sender().solicited
```

**For broad hunts, strip the N-of and NLU requirements.** Start with the core structural signals, see what you catch, then tighten:

```mql
// Hunt: broad sweep first
type.inbound
and strings.ilike(body.current_thread.text, "*gift card*")
and strings.ilike(body.current_thread.text, "*reimburse*", "*pay*back*")
and (
  sender.email.domain.root_domain in $free_email_providers
  or profile.by_sender().prevalence != "common"
)
```

---

### ML Function Guidance

**`ml.nlu_classifier` — intents vs topics vs tags**

- `.intents` — what the message is trying to do: `bec`, `cred_theft`, `callback_scam`, `urgency`, `financial_request`, `job_scam`, `extortion`, `steal_pii`, `vendor_fraud`, `recruiting`
- `.topics` — content category: `"B2B Cold Outreach"`, `"Events and Webinars"`, `"Newsletter"`, `"Professional and Career Development"`, `"Advertising and Promotions"` — good for graymail
- `.tags` — specific named entities: `gift_card`, `payment_card`, `simulation`

Confidence values: `"high"`, `"medium"`, `"low"`. In production rules, gate on `("high", "medium")`. For hunts, try just `.name == "bec"` without confidence filter to cast wider.

**`ml.link_analysis` — cost and modes**

Link analysis launches a headless browser. It is the most expensive ML function in MQL. Always pre-filter links before calling it:

```mql
// EXPENSIVE — calls link analysis on every single link
any(body.links, ml.link_analysis(.href_url.url).credphish.disposition == "phishing")

// BETTER — pre-filter to only suspicious links before running the headless browser
any(filter(body.links,
           not .href_url.domain.root_domain in $org_domains
           and not strings.istarts_with(.href_url.url, "mailto:")
    ),
    ml.link_analysis(.href_url.url).credphish.disposition == "phishing"
)
```

**Default vs aggressive mode** — they behave and cache differently:

```mql
// Default mode — follows standard redirects
ml.link_analysis(.href_url.url).credphish.disposition

// Aggressive mode — follows more redirects, harder pursuit of final destination
ml.link_analysis(.href_url.url, mode="aggressive").credphish.disposition
```

Always test both when investigating a suspicious link in the rule editor. They are cached independently — one may have a result when the other returns `unknown`.

---

### Link Analysis Specifics

**What the link analysis result fields mean:**

- `submitted` — whether the URL was queued for analysis at message ingestion time
- `retrieved` — whether the page was successfully fetched/crawled
- `analyzed` — whether credphish classification was completed
- `credphish.disposition` — the verdict: `"phishing"`, `"safe"`, `"inconclusive"`, `"unknown"`, `"error"`

If `submitted: false` and `retrieved: false` and `credphish.disposition: "unknown"`, the URL was **never analyzed** at ingestion. This happens with:
- Click-tracking wrappers (SendGrid `ct.sendgrid.net/ls/click`, etc.) — not followed by default mode
- URLs that were not deemed high-risk enough to analyze during ingestion scoring
- Aged messages: if a message was ingested days after sending, the URL may already be down

**Caching behavior:** Link analysis results are cached at scan time. When you click "View" on a link in the Message Detail View, the UI makes a live request to the URL (not the cached version) — which means if the URL is dead or the campaign is over, you'll see a 404. The MQL result is the cached ingestion-time analysis. To see what was cached, query MQL in the Rule Editor against the specific message.

**Click-tracking wrappers:** SendGrid, Mailchimp, and similar ESPs wrap destination URLs. Default link analysis usually does not follow these through. Aggressive mode may resolve them.

**Timing considerations:** If you're hunting a campaign that ran 4 days ago, link analysis `credphish.disposition` may be `"unknown"` even on confirmed phishing messages — the attacker may have pulled infrastructure by the time Sublime analyzed it or you ran the hunt. Use the URL structure and domain age signals as primary indicators in those cases.

---

### Body Field Selection

Three main text fields and when to use each:

| Field | Contents | Best For |
|---|---|---|
| `body.current_thread.text` | Latest reply only — quoted/forwarded text stripped | NLU classification, BEC detection, content matching in active conversation |
| `body.html.display_text` | All rendered visible text, including quoted thread | Searching full thread history, finding text buried in replies |
| `body.html.raw` | Raw HTML source | Finding obfuscated content, hidden elements, specific HTML patterns |

**For NLU, always use `body.current_thread.text`.** If you use `body.html.display_text` or the full body, the classifier will pick up quoted thread content and can misclassify legitimate emails based on a previous phishing message someone replied to.

**For string searches across the whole email thread**, `body.html.display_text` is more complete but slower. Use `body.current_thread.text` first; only fall back to `display_text` if you need to catch patterns buried in the thread history.

**For HTML structure or encoding tricks**, use `body.html.raw`:

```mql
// Detect base64 obfuscation in HTML
strings.icontains(body.html.raw, "fromCharCode")
or strings.icontains(body.html.raw, "unescape")
or strings.icontains(body.html.raw, "atob(")
```

---

### Hunt-Specific Behavior (What's Different in Hunt Context)

**`profile.by_sender()` reflects current state, not historical state.**

When you run a hunt over messages from 3 months ago, `profile.by_sender().prevalence` returns the sender's prevalence *right now*, not what it was at the time the message was delivered. A sender who was `"new"` when they sent the phishing campaign will now show as `"common"` if they've continued emailing your org since. This means:

- Hunt rules with `prevalence in ("new", "outlier")` will miss attacks from senders that have since built up a history
- For historical hunts, lean on structural signals (domain age, auth headers, link patterns) over behavioral profile signals
- `profile.by_sender().solicited` has the same limitation — a sender may be solicited now because someone emailed them back after the original attack was reviewed as benign

**List variables may not be populated in demo/new tenants.**

`$org_vips`, `$org_display_names`, `$org_domains`, and custom lists need to be populated for list-based checks to work. In a fresh HIP tenant or demo environment, these may be empty — rules using them will always return false until the lists are configured.

**Validate in the Rule Editor before running as a Hunt.**

The Rule Editor lets you run MQL against a specific message and see why it matched or didn't. Use it to confirm a rule works on at least one known-good example before launching a multi-week hunt job. Hunting is async and you want to catch bad MQL before waiting for results.

---

### Naming, Tagging, and Rule Style

**Rule name format:** `"AttackType: Specific description of the pattern"`

Examples from production:
- `"BEC/Fraud: Gift card scam with declined card and urgent excuse"`
- `"Hunt: Microsoft unusual sign-in activity alerts"`
- `"Attachment: ICS file with meeting prefix"`
- `"Impersonation: Internal corporate services"`

Hunt rules get the `"Hunt: "` prefix so they're easy to filter out of production rule lists.

**YAML filename:** snake_case, attack-type first:
- `bec_gift_card_reimbursement_scam.yml`
- `hunt_zohostratus_redirect_ip.yml`
- `attachment_ics_meeting_invite.yml`

**YAML structure** — always include these fields for community-style rules:

```yaml
name: "BEC/Fraud: Gift card scam"
description: |
  Two-sentence description: what attack it detects, and what specific pattern makes it distinctive.
type: "rule"
severity: "high"       # high for confirmed patterns, medium for hunting
source: |
  type.inbound
  // ... MQL here
attack_types:
  - "BEC/Fraud"
tactics_and_techniques:
  - "Social engineering"
  - "Impersonation: Executive"
detection_methods:
  - "Content analysis"
  - "Natural Language Understanding"
  - "Sender analysis"
tags:
  - "type:attack:bec"
id: "uuid-here"
```

**In-MQL comments** use `//` and should explain the *intent* of a condition group, not just restate it:

```mql
// gift card terminology (required — this is the hard gate)
and strings.ilike(body.current_thread.text, "*gift card*", "*egift*")

// 2 of 5 additional scam signals — don't require all to avoid brittleness
and 2 of (...)
```

**Severity guidelines:**
- `high` — confident detection of a known attack pattern, validated against real samples
- `medium` — hunting/broad detection, expected FP rate, needs tuning
- `low` / `info` — monitoring, graymail, telemetry rules with no remediation action

---

*Section added May 2026 — extracted from real detection rule development sessions*

---

## 6. Common Workflows

### Workflow 1: Hunt for a Threat Pattern

1. Write an MQL expression capturing the threat (test it in the Sublime rule editor first)
2. `POST /v0/hunt-jobs` with `source`, `range_start_time`, `range_end_time`, `name`
3. Poll `GET /v0/hunt-jobs/{id}` until `status == "COMPLETED"`
4. Fetch `GET /v0/hunt-job-results?hunt_job_id={id}`
5. Review matching messages and take action if needed

```python
import time, requests

BASE_URL = "https://platform.sublime.security"
HEADERS = {"Authorization": "Bearer <API_KEY>", "Content-Type": "application/json"}

# Start hunt
payload = {
    "name": "BEC Hunt Q1 2026",
    "source": """type.inbound
and not profile.by_sender().solicited
and any(ml.nlu_classifier(body.current_thread.text).intents,
  .name == "bec" and .confidence == "high"
)""",
    "range_start_time": "2026-01-01T00:00:00Z",
    "range_end_time": "2026-03-31T23:59:59Z",
    "private": True
}
resp = requests.post(f"{BASE_URL}/v0/hunt-jobs", headers=HEADERS, json=payload)
job_id = resp.json()["id"]
print(f"Hunt started: {job_id}")

# Poll for completion
while True:
    status = requests.get(f"{BASE_URL}/v0/hunt-jobs/{job_id}", headers=HEADERS).json()["status"]
    if status == "COMPLETED":
        break
    elif status in ("FAILED", "CANCELED"):
        raise Exception(f"Hunt failed: {status}")
    print(f"Status: {status}. Waiting...")
    time.sleep(5)

# Get results
results = requests.get(
    f"{BASE_URL}/v0/hunt-job-results",
    headers=HEADERS,
    params={"hunt_job_id": job_id}
).json()
print(f"Found {len(results.get('results', []))} matching messages")
```

### Workflow 2: Review Flagged Message Groups

1. `GET /v0/message-groups` to list open groups
2. For each group, inspect the matched rule and sample messages
3. `POST /v0/message-groups/review` with verdict and optional action

```python
# List open message groups
groups = requests.get(
    f"{BASE_URL}/v0/message-groups",
    headers=HEADERS,
    params={"limit": 50}
).json()

for group in groups.get("message_groups", []):
    print(f"ID: {group['id']}, Rule: {group.get('rule_name')}, Count: {group.get('message_count')}")

# Review a group as malicious + trash
requests.post(
    f"{BASE_URL}/v0/message-groups/review",
    headers=HEADERS,
    json={
        "message_group_id": group["id"],
        "verdict": "malicious",
        "action": "trash"
    }
)
```

### Workflow 3: Create a Detection Rule

1. Write and test your MQL expression (use the rule editor in the dashboard)
2. `POST /v0/rules` with the rule definition
3. Verify it appears and is active via `GET /v0/rules?search=<name>`

```python
rule = {
    "name": "Callback Scam - High Confidence",
    "description": "Detects callback scam emails using NLU with phone number confirmation",
    "source": """type.inbound
and any(ml.nlu_classifier(body.current_thread.text).intents,
  .name == "callback_scam" and .confidence == "high"
)
and regex.contains(body.current_thread.text, '\\+?[\\d\\s\\-\\(\\)]{10,}')""",
    "severity": "medium",
    "type": "rule",
    "active": True,
    "tags": ["type:attack:callback_scam"]
}
resp = requests.post(f"{BASE_URL}/v0/rules", headers=HEADERS, json=rule)
print(f"Created rule: {resp.json()['id']}")
```

### Workflow 4: Manage Threat Intel Lists

```python
# List all custom lists
lists = requests.get(f"{BASE_URL}/v0/lists", headers=HEADERS).json()
for l in lists.get("lists", []):
    print(f"{l['id']}: {l['name']} ({l.get('entry_count', 0)} entries)")

# Add a malicious domain to a list
requests.post(
    f"{BASE_URL}/v0/lists/{list_id}/entries/entry",
    headers=HEADERS,
    json={"string": "malicious-domain.com"}
)

# Check if an entry exists
resp = requests.get(
    f"{BASE_URL}/v0/lists/{list_id}/entries/entry",
    headers=HEADERS,
    params={"string": "malicious-domain.com"}
)
print(f"Exists: {resp.json().get('exists', False)}")
```

### Workflow 5: Take Action on a Message

```python
# Quarantine a specific message (async)
resp = requests.post(
    f"{BASE_URL}/v0/messages/{message_id}/actions",
    headers=HEADERS,
    json={"action": "quarantine"}
)
task_id = resp.json()["task_id"]

# Poll task status
while True:
    task = requests.get(f"{BASE_URL}/v0/tasks/{task_id}", headers=HEADERS).json()
    if task["status"] == "COMPLETED":
        print("Message quarantined successfully")
        break
    elif task["status"] == "FAILED":
        print(f"Action failed: {task.get('error')}")
        break
    time.sleep(2)
```

### Workflow 6: Analyze an Attachment with BinExplode

```python
# Upload a file for static analysis
with open("suspicious.docm", "rb") as f:
    resp = requests.post(
        f"{BASE_URL}/v0/binexplode/scan",
        headers={"Authorization": f"Bearer {API_KEY}"},
        files={"file": f}
    )
scan_id = resp.json()["id"]

# Poll for results
while True:
    result = requests.get(
        f"{BASE_URL}/v0/binexplode/scan/{scan_id}",
        headers=HEADERS
    ).json()
    if result.get("status") == "COMPLETED":
        print(f"Malicious: {result.get('malicious')}")
        print(f"Indicators: {result.get('indicators', [])}")
        break
    time.sleep(3)
```

---

## 7. Key Public Resources

| Resource | URL |
|---|---|
| MQL Message Data Model (full field schema) | `https://docs.sublime.security/reference/getmessagedatamodel-1.md` |
| API Reference Docs | `https://docs.sublimesecurity.com/reference/introduction` |
| Community Rules Repo | `https://github.com/sublime-security/sublime-rules` |
| CLI / Analysis API | `pip3 install sublime-cli` |
| Dashboard (NA) | `https://platform.sublime.security` |

### Fetching the MQL Message Data Model Reference

```bash
curl https://docs.sublime.security/reference/getmessagedatamodel-1.md -o sublime_mdm_reference.md
```

### Importing to Postman

See the [API Reference Docs](https://docs.sublimesecurity.com/reference/introduction) for importing endpoints into Postman.
1. Open Postman → Import
2. Set a collection variable `base_url` to your regional base URL
3. Set a collection variable `api_key` and configure Bearer auth

---

## 8. Using the Sublime CLI

The CLI wraps the analysis API for quick MQL testing and message analysis.

```bash
pip3 install sublime-cli

# Analyze a .eml file against community rules
sublime analyze --eml path/to/email.eml

# Test a specific MQL rule against an .eml
sublime analyze --eml path/to/email.eml --rule path/to/rule.yml

# Auth
sublime auth --api-key <your-api-key>
```

---

## 9. MQL Writing Tips

1. **Always gate on `type.inbound`** (or `outbound`/`internal`) unless intentionally matching all directions.
2. **`profile.by_sender().solicited`** is the best single signal for "is this expected email" — always consider adding `not profile.by_sender().solicited` to reduce false positives.
3. **Combine ML signals**: NLU alone can be noisy; add structural checks (new sender, free email provider, no DMARC, etc.) for precision.
4. **Use `prevalence` for new sender detection**: `profile.by_sender().prevalence == "new"` targets first-time senders with zero org history.
5. **`body.current_thread.text`** is pre-processed to strip quoted replies — prefer it over `body.html.display_text` for NLU inputs.
6. **Array lambdas use `.` prefix**: Inside `any(array, ...)`, reference the current element's fields with `.field` (e.g., `.name`, `.href_url.url`).
7. **Test in the dashboard rule editor** before deploying — it provides real-time syntax validation and test message matching.
8. **Link analysis is expensive** — scope `body.links` with a `filter()` before calling `ml.link_analysis()` when possible.
9. **`$list_name` syntax** references both system and custom lists inline in MQL.
10. **Rules are OR logic at the platform level** — if any active rule matches a message, it generates a detection. Keep rules focused.

---

## 10. Rule YAML Structure

Community rules follow this YAML schema:

```yaml
name: "Attack: Credential Phishing - New Sender with Phishing Link"
description: |
  Detects credential phishing emails from first-time senders containing
  links confirmed as phishing by Sublime's headless browser analysis.
type: rule
severity: high
source: |
  type.inbound
  and profile.by_sender().prevalence == "new"
  and not profile.by_sender().solicited
  and any(body.links,
    ml.link_analysis(.href_url.url).credphish.disposition == "phishing"
  )
tags:
  - "type:attack:credential_phishing"
  - "sender:new"
references:
  - "https://attack.mitre.org/techniques/T1566/002/"
```

**Type values:** `rule` (detection rule), `signal` (informational, no alert), `exclusion` (suppress matching)

**Severity values:** `critical`, `high`, `medium`, `low`, `info`

---

## 11. Pagination Patterns

### Cursor Pagination (message-groups/search)
```python
results = []
next_page_token = None

while True:
    params = {"limit": 100}
    if next_page_token:
        params["next_page_token"] = next_page_token
    
    resp = requests.get(f"{BASE_URL}/v0/message-groups/search", headers=HEADERS, params=params).json()
    results.extend(resp.get("message_groups", []))
    
    next_page_token = resp.get("next_page_token")
    if not next_page_token:
        break

print(f"Total: {len(results)}")
```

### Offset Pagination (rules)
```python
rules = []
offset = 0
limit = 500

while True:
    resp = requests.get(
        f"{BASE_URL}/v0/rules",
        headers=HEADERS,
        params={"limit": limit, "offset": offset}
    ).json()
    
    batch = resp.get("rules", [])
    rules.extend(batch)
    
    if len(batch) < limit:
        break
    offset += limit

print(f"Total rules: {len(rules)}")
```

---

## 12. Error Handling Best Practices

```python
import requests
from requests.exceptions import RequestException

def sublime_request(method, path, base_url, headers, **kwargs):
    """Make a Sublime API request with error handling."""
    url = f"{base_url}{path}"
    try:
        resp = requests.request(method, url, headers=headers, timeout=30, **kwargs)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            raise ValueError("Invalid API key — check your SUBLIME_API_KEY")
        elif e.response.status_code == 404:
            raise ValueError(f"Resource not found: {path}")
        elif e.response.status_code == 422:
            raise ValueError(f"Validation error: {e.response.json()}")
        elif e.response.status_code == 429:
            raise RuntimeError("Rate limited — back off and retry")
        raise
    except RequestException as e:
        raise RuntimeError(f"Network error: {e}")
```

---

## 13. Integration Patterns

### SOAR Integration
Sublime's API fits naturally into SOAR platforms (Splunk SOAR, Palo Alto XSOAR, etc.):
- **Trigger:** Webhook or polling on `GET /v0/message-groups` for new open groups
- **Enrich:** `GET /v0/messages/{id}` for full MDM data
- **Decide:** SOAR playbook logic
- **Act:** `POST /v0/message-groups/review` with verdict/action

### SIEM Export
Correlate Sublime detections with SIEM events using:
- Message IDs and sender/recipient metadata from the MDM
- Rule names and severities from message group data
- Timestamps from message metadata

### Custom Alerting
Poll `GET /v0/message-groups` on a schedule and push to Slack/PagerDuty/Teams for high-severity open groups.

---

*Last updated: May 2026 | Source: Sublime Security public documentation and API spec*
*MQL Message Data Model reference: https://docs.sublime.security/reference/getmessagedatamodel-1.md*
