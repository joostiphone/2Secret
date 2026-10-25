# Agent Access: AI tools and 2Secret

AI tools such as Claude Code, Claude Desktop, Cursor, Codex and Gemini CLI can
use the items in your vault through the [Model Context Protocol](https://modelcontextprotocol.io)
(MCP). 2Secret asks you before a secret leaves the vault; the tool never sees a
password it was not given, and whatever a program ran with stays out of the
conversation.

## How it works

```
AI tool (Claude Code, Cursor, …)
   │ MCP over stdin/stdout
   ▼
2secret mcp                       one Ed25519 key per AI tool, kept in the data folder
   │ access.sock (a named pipe on Windows), JSON-RPC, one line per message
   ▼
2Secret desktop app               asks you; remembers agents, permissions and a log,
                                  encrypted with your account key
```

- **Searching needs no question.** Once you have allowed a tool to connect,
  it can search the titles, user names, websites and tags of your items and
  see which fields exist. It never gets the value of a password, one-time
  code or note that way.
- **Every secret needs your yes.** Reading a field, getting a one-time code,
  saving or changing an item: 2Secret shows which tool asks, which item and
  which fields, and the reason the tool gives. You allow it once, for these
  items until 2Secret locks, or for these items for 8 hours. Saving a new item
  is approved one at a time.
- **Programs get secrets, the model does not.** `run_command` runs a program
  with environment variables whose values are `2s://` references (see
  [docs/CLI.md](CLI.md), *Secret references*). 2Secret asks you once for all
  of them, the program gets the real values, and in the output the tool reads
  back the values are replaced by their references.
- **Optionally Touch ID, Face ID or Windows Hello** before an agent gets a
  secret (on when biometric unlock is set up).
- **Everything is logged** under *Settings → Desktop app → AI agents*: which
  tool asked for what, and what you answered. There you also see the connected
  tools, their standing permissions, and revoke them.
- **Locking ends everything.** While 2Secret is locked no request is answered
  (the tool is told to ask you to unlock); "until 2Secret locks" permissions
  are forgotten, 8-hour permissions resume after unlocking.

## Setting up

1. Install the 2Secret command line (`2secret`, from the
   [releases](https://github.com/joostiphone/2Secret/releases)) next to the
   desktop app. Both use the same data folder.
2. In the desktop app: *Settings → Desktop app → AI agents → Turn on*.
3. Add 2Secret to your AI tool as an MCP server with the command `2secret mcp`:

**Claude Code**

```sh
claude mcp add 2secret -- 2secret mcp
```

**Claude Desktop** (`claude_desktop_config.json`), **Cursor** (`.cursor/mcp.json`
or the MCP settings), **Windsurf** and most other tools:

```json
{
  "mcpServers": {
    "2secret": { "command": "2secret", "args": ["mcp"] }
  }
}
```

**Codex CLI** (`~/.codex/config.toml`):

```toml
[mcp_servers.2secret]
command = "2secret"
args = ["mcp"]
```

**Gemini CLI** (`~/.gemini/settings.json`): the same `mcpServers` object as
above.

The first time the tool calls 2Secret, the app asks whether it may connect, and
shows the program on the other end (for example `claude`, via `2secret`). The
tool is then listed under *AI agents*. Each AI tool gets its own key
(`agent-key-<tool>.json` in the data folder), so Claude Code and Cursor are two
different agents with their own permissions.

`2secret agent status` shows whether the app is reachable and which agents are
known on this computer. `TWOSECRET_HOME` points both the app and `2secret mcp`
at another data folder.

## The tools

| Tool | Asks you? | What it does |
|---|---|---|
| `search_items` | no | Items by words, website (matched like autofill), vault or type; never secrets or notes |
| `get_item` | no | One item; secret fields are listed as `secret: true` without a value |
| `read_field` | yes | One value: a password, API key, custom field, the notes or `otp` (current code). The value becomes visible to the model. |
| `get_otp` | yes | The current one-time code and how long it is valid |
| `generate_password` | no | A random password, passphrase or PIN; nothing is stored |
| `save_login` | yes | A new item; with `generate_password` 2Secret makes the password and the model never sees it |
| `update_item` | yes | Change title, user name, password, notes, websites or fields |
| `run_command` | yes, once for all references | Run a program with `2s://` references in its environment; secrets are filtered out of the output |
| `agent_status` | no | Whether 2Secret is reachable and as which agent this connection is known |

Items are named by id (from `search_items`), exact title or a `2s://` reference.

## Without the desktop app

`2secret mcp --standalone` works on the vault directly, through the shell
session (`eval "$(2secret unlock)"`) or `TWOSECRET_PASSWORD`. Nobody can be
asked for permission then, so it only searches, shows items without secrets
and generates passwords. `--allow-run` adds `run_command`, which then hands
secrets to programs without anyone approving: use it only on a machine where
the AI tool may do what you may do.

## What this does and does not protect

Agent Access treats the AI tool like any other program you run: it can ask,
and you decide. Keep in mind:

- A tool that controls your computer (a "computer use" agent that clicks
  for you) can click *Allow* itself. Turn on the biometric question for
  agents, and keep *Deny* as the default it is: Enter and Escape refuse.
- `read_field` puts the value in the conversation with the AI provider.
  Prefer `run_command` with references, or `save_login` with
  `generate_password`, so the model never holds the secret.
- 2Secret shows the path of the program on the other end of the socket and
  the program that started it, as the operating system reports them. It
  cannot verify a program's claims about its own name beyond that.
- Agent Access is off by default and only in the desktop apps (macOS,
  Windows, Linux). The web vault, the browser extension and the phone apps
  have no socket.

See [docs/SECURITY.md](SECURITY.md) for the full picture.
