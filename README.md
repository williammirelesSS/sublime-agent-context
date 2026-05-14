# Sublime Security Agent Context

Tools for giving any AI agent deep knowledge of Sublime Security — and for connecting AI agents directly to a Sublime tenant via MCP.

---

## What's in this folder

| File | Purpose |
|---|---|
| `sublime_expert_context.md` | Drop-in context doc — paste into any AI agent to make it a Sublime expert |
| `sublime_mcp_server.py` | Production-ready FastMCP server wrapping the Sublime v0 API |
| `README.md` | This file |

---

## 1. `sublime_expert_context.md` — Context injection for any AI

This is a comprehensive system-prompt-style document covering:
- What Sublime Security is and how it works
- The Message Data Model (MDM) field reference
- Complete v0 API endpoint reference with auth and regional URLs
- MQL cheat sheet with 10+ example detection rules
- Common workflows (hunting, triaging, rule creation, list management)
- Python code patterns for all major operations
- Links to all public resources

### How to use it

**Option A — Paste into any chat:**
1. Open the file
2. Copy the entire contents
3. Paste it as your first message (or system prompt) in Claude, ChatGPT, Cursor, Gemini, etc.
4. The agent now has expert-level Sublime knowledge for the rest of the session

**Option B — System prompt (Claude Projects, OpenAI Custom GPTs, etc.):**
1. In Claude Projects: paste the document into the Project Instructions
2. In a Custom GPT: paste into the System Instructions field
3. Every conversation in that project/GPT will start with full Sublime context

**Option C — Cursor `.cursorrules` or rules file:**
1. Copy the relevant sections into your `.cursor/rules/` directory
2. Cursor will automatically inject them when working on Sublime-related code

---

## 2. Fetching the MQL Message Data Model Reference

The full MQL Message Data Model reference (field schema for all MQL rules) is publicly accessible (no auth required):

```bash
curl https://docs.sublime.security/reference/getmessagedatamodel-1.md -o sublime_mdm_reference.md
```

This gives you the complete field schema used by MQL rules — every field, type, and description available for writing detection logic.

### Importing to Postman

1. Open **Postman → Import**
2. Use the [API Reference Docs](https://docs.sublimesecurity.com/reference/introduction) to import endpoints
3. Set collection variables:
   - `base_url` → your regional base URL (e.g. `https://uk.platform.sublime.security`)
   - `api_key` → your API key
4. Configure collection-level Bearer auth: `{{api_key}}`

---

## 3. `sublime_mcp_server.py` — MCP server for AI agents

A production-ready [FastMCP](https://github.com/jlowin/fastmcp) server that exposes Sublime Security's v0 API as MCP tools. Connect it to Claude Desktop, Cursor, or any MCP-compatible agent.

### Tools exposed

| Tool | Description |
|---|---|
| `list_message_groups` | List open/reviewed flagged message groups |
| `search_message_groups` | Search groups by keyword, hash, domain |
| `review_message_group` | Classify a group (malicious/benign/spam/etc.) with optional action |
| `get_message` | Retrieve full MDM for a specific message |
| `action_on_message` | Trash, quarantine, restore, or banner a message |
| `start_hunt` | Start an MQL retrospective hunt job |
| `get_hunt_status` | Poll hunt job completion status |
| `get_hunt_results` | Fetch results from a completed hunt |
| `run_hunt_and_wait` | Start a hunt and block until complete (convenience wrapper) |
| `list_rules` | List detection rules with optional search filter |
| `create_rule` | Create a new MQL detection rule |
| `list_lists` | List threat intel lists |
| `add_list_entry` | Add a domain/IP/hash to a list |
| `check_list_entry` | Check if an entry exists in a list |
| `get_task_status` | Poll any async task |
| `get_binexplode_results` | Get static analysis results for an attachment |
| `get_platform_info` | Confirm connection details and auth status |

### Installation

```bash
pip install fastmcp httpx
```

### Environment variables

```bash
export SUBLIME_API_KEY="your-api-key-here"

# Optional — defaults to NA-East if not set
export SUBLIME_BASE_URL="https://uk.platform.sublime.security"
```

Generate an API key in the Sublime dashboard: **Automate → API → New Key**

Regional base URLs:
| Region | URL |
|---|---|
| NA-East (default) | `https://platform.sublime.security` |
| UK | `https://uk.platform.sublime.security` |
| EU | `https://eu.platform.sublime.security` |
| AU | `https://au.platform.sublime.security` |
| Canada | `https://ca.platform.sublime.security` |
| NA-West | `https://na-west.platform.sublime.security` |

### Running the server

```bash
python sublime_mcp_server.py
```

### Connecting to Cursor

Add to your Cursor MCP config (`~/.cursor/mcp.json` or the workspace `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "sublime-security": {
      "command": "python",
      "args": ["/path/to/sublime_mcp_server.py"],
      "env": {
        "SUBLIME_API_KEY": "your-api-key-here",
        "SUBLIME_BASE_URL": "https://platform.sublime.security"
      }
    }
  }
}
```

### Connecting to Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "sublime-security": {
      "command": "python",
      "args": ["/path/to/sublime_mcp_server.py"],
      "env": {
        "SUBLIME_API_KEY": "your-api-key-here",
        "SUBLIME_BASE_URL": "https://platform.sublime.security"
      }
    }
  }
}
```

Then restart Claude Desktop. You'll see the Sublime tools available in the tool picker.

### Example agent prompts (once connected)

```
"List all open message groups and summarize by severity."

"Hunt for BEC emails from the past 30 days using NLU with high confidence."

"Search for message groups matching 'invoice' and review any that look like graymail."

"Create a detection rule for callback scam emails with phone numbers."

"Check if evil-domain.com is in our blocklist."

"Show me all high-severity rules that are currently active."
```

---

## 4. Public Resources

| Resource | URL |
|---|---|
| MQL Message Data Model | https://docs.sublime.security/reference/getmessagedatamodel-1.md |
| API Reference | https://docs.sublimesecurity.com/reference/introduction |
| Community Rules Repo | https://github.com/sublime-security/sublime-rules |
| CLI (`sublime-cli`) | `pip3 install sublime-cli` |

---

## 5. Quick Auth Test

Verify your API key and region are configured correctly:

```bash
curl -s \
  -H "Authorization: Bearer $SUBLIME_API_KEY" \
  https://platform.sublime.security/v0/rules?limit=1 | python -m json.tool
```

Or from Python:

```python
import os, requests
r = requests.get(
    "https://platform.sublime.security/v0/rules",
    headers={"Authorization": f"Bearer {os.environ['SUBLIME_API_KEY']}"},
    params={"limit": 1}
)
print(r.status_code, r.json())
```
