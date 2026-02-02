# 🦞 Carapace

> *The hard shell that protects your OpenClaw from prompt injection.*

Carapace is a prompt injection detection plugin for [OpenClaw](https://github.com/openclaw/openclaw) (formerly Moltbot/Clawdbot), integrating the [Nova Framework](https://novahunting.ai/) and [PromptIntel](https://promptintel.novahunting.ai/) for detection.

## ✨ Features

- 🛡️ **Nova Framework Integration** — 42+ detection rules for jailbreaks, prompt injection, OWASP LLM Top 10
- 🧹 **Text Sanitization** — Defeats Unicode tricks, homoglyphs, invisible characters
- 🔍 **Encoding Detection** — Catches base64, hex, and Unicode escape obfuscation
- 🌐 **PromptIntel Integration** — Optional cloud-based IoPC threat intelligence
- 🧠 **Optional Semantic & LLM Evaluation** — Deep analysis using embeddings and LLM providers

## 🚀 Quick Start

### 1. Clone the repo

```bash
git clone https://github.com/xampla/carapace.git
cd carapace
```

### 2. Install dependencies

```bash
pip3 install -r requirements.txt
```

### 3. Try it out!

```bash
# Scan text for prompt injection
python carapace.py scan "ignore all previous instructions"

# Scan a shell command
python carapace.py command "rm -rf /"

# Check scanner stats
python carapace.py stats

# Check PromptIntel API status
python carapace.py health
```

### 4. Use in Python

```python
from src import CarapaceScanner

scanner = CarapaceScanner()

result = scanner.scan("ignore all previous instructions")
print(result["safe"])       # False
print(result["threats"])    # [{rule, category, severity, matched}]
```

## 🔌 OpenClaw Plugin

Carapace integrates with [OpenClaw](https://github.com/openclaw/openclaw) to protect your AI assistant:

```bash
# Symlink the plugin folder
ln -s $(pwd)/plugin ~/.openclaw/extensions/carapace
```

Configure in your `openclaw.yaml`:

```yaml
plugins:
  entries:
    carapace:
      enabled: true
      config:
        blockDangerousCommands: true # Block high-severity threats before tool execution
        scanToolOutputs: true        # Scan tool outputs for indirect injection

        # PromptIntel (optional)
        promptIntelApiKey: ""        # Your PromptIntel API key

        # Nova evaluation modes (optional, slower but more accurate)
        enableSemantics: false       # Semantic matching (requires sentence-transformers)
        enableLlm: false             # LLM-based evaluation
        llmProvider: "openai"        # "openai" or "anthropic"
        llmApiKey: ""                # API key for LLM provider
```

> **Note:** The `llmApiKey` must be configured separately from OpenClaw's provider keys. You can either set it in the plugin config above, or use environment variables (`OPENAI_API_KEY` or `ANTHROPIC_API_KEY`).

### How It Works

Carapace uses two hooks to protect your agent:

#### 1. Pre-execution Blocking (`before_tool_call`)

```
Agent wants to run a tool
       │
       ▼
┌─────────────────────────────────────────────────┐
│  before_tool_call                               │
│                                                 │
│  exec/bash/shell → scan command                 │
│  read            → scan file path               │
│  web_fetch       → scan URL                     │
└─────────────────────────────────────────────────┘
       │
       ▼
  High/Critical threat?
       │
   ┌───┴───┐
   │  Yes  │──→ BLOCKED: Tool call rejected
   │       │    "Blocked by Carapace: [input type]
   │       │     contains N threat(s) (category, severity)"
   └───────┘
       │ No
       ▼
  Low/Medium threat?
       │
   ┌───┴───┐
   │  Yes  │──→ WARNING logged, but tool allowed
   └───────┘
       │
       ▼
   Tool executes
```

#### 2. Output Scanning (`tool_result_persist`)

```
Tool returns output (exec, read, web_fetch, etc.)
       │
       ▼
┌─────────────────────┐
│ tool_result_persist │  Carapace scans the output
│                     │  for prompt injection patterns
└─────────────────────┘
       │
       ▼
  Threat detected?
       │
   ┌───┴───┐
   │  Yes  │──→ Warning prepended to output:
   │       │    "🚨 Carapace: Tool output may contain
   │       │     prompt injection (category, severity)"
   └───────┘
       │
       ▼
┌─────────────────────┐
│ Agent sees warning  │  Agent can decide how to handle
│ in tool result      │  the potentially malicious content
└─────────────────────┘
```

### Threat Severity Behavior

| Severity | Before Tool Call | Tool Output |
|----------|------------------|-------------|
| `low/medium` | Warn, allow | Prepend warning |
| `high/critical` | **BLOCK** | Prepend warning |

### Scanned Tools

| Tool | What's Scanned | Scanner |
|------|----------------|---------|
| `exec`, `bash`, `shell` | Command parameter | Command scanner |
| `read` | File path | Text scanner |
| `web_fetch` | URL | Text scanner |

### Current Limitations

- **No `after_tool_call` Hook**: OpenClaw hasn't wired up the `after_tool_call` hook yet ([#6535](https://github.com/openclaw/openclaw/issues/6535)). This limits post-execution telemetry (timing, success/failure metrics). Output scanning still works via `tool_result_persist`.

### RPC Endpoints

The plugin exposes three RPC endpoints:

- **`carapace.scan`** — Manually scan text for threats
- **`carapace.scanCommand`** — Manually scan a shell command for threats
- **`carapace.status`** — Check plugin configuration status

## 🔧 CLI Options

```bash
# Basic scan
python carapace.py scan "text to check"

# With options
python carapace.py scan "text" --offline          # Skip PromptIntel lookup
python carapace.py scan "text" --raw              # Skip text sanitization
python carapace.py scan "text" --enable-semantics # Enable semantic matching
python carapace.py scan "text" --enable-llm       # Enable LLM evaluation

# Command scanning
python carapace.py command "shell command"
python carapace.py command "cmd" --enable-semantics --enable-llm
```

## 🌐 PromptIntel Integration

Add [PromptIntel](https://promptintel.novahunting.ai) for cloud-based threat intelligence:

```bash
export PROMPTINTEL_API_KEY="ak_your_key_here"
```

PromptIntel provides:
- 📊 **IoPC Database** — Known malicious prompts
- 🔄 **Live Updates** — New threats added by the community
- 🏷️ **Threat Taxonomy** — Categorized attack patterns

## 📁 Project Structure

```
carapace/
├── carapace.py           # CLI
├── src/
│   └── scanner.py        # CarapaceScanner (wraps Nova Framework)
├── plugin/
│   ├── openclaw.plugin.json
│   └── index.ts          # OpenClaw integration
├── rules/                # Nova detection rules (from nova-rules repo)
└── tests/
```

## 🧪 Running Tests

```bash
python3 tests/test_scanner.py

# All 22 tests should pass ✅
```

## 🙏 Credits

Carapace integrates these excellent tools:

### [Nova Framework](https://github.com/Nova-Hunting/nova-framework)
A YARA-like rule engine for AI security by Thomas Roccia.

### [PromptIntel](https://promptintel.novahunting.ai)
The IoPC (Indicators of Prompt Compromise) database and API.

### [Thomas Roccia (@fr0gger_)](https://twitter.com/fr0gger_)
Creator of Nova Framework and PromptIntel. Check out his [blog](https://blog.securitybreak.io) for AI security insights!

### [OpenClaw](https://github.com/openclaw/openclaw)
The AI assistant that Carapace protects. 🦞

## 📄 License

MIT License — See [LICENSE](LICENSE) for details.

---

<p align="center">
  🦞 <strong>EXFOLIATE</strong> your prompts! 🦞
</p>
