# Agent Access: AI tools and 2Secret

AI tools such as Claude Code, Claude Desktop, Cursor, Codex and Gemini CLI can
use the items in your vault through the [Model Context Protocol](https://modelcontextprotocol.io)
(MCP). 2Secret asks you before a secret leaves the vault; the tool never sees a
password it was not given, and whatever a program ran with stays out of the
conversation. An AI agent that drives your browser can let 2Secret sign you in
on a website without ever seeing the password (*Filling a login in your
browser* below).

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

## Filling a login in your browser

An AI agent that works in your browser (Claude for Chrome, Perplexity Comet,
ChatGPT Atlas, a browser driven by Playwright or Browser Use, …) needs to sign
in to websites. With `fill_login` it does not need the password for that:

```
AI agent ──MCP──▶ 2secret mcp ──▶ 2Secret app      "Claude wants to sign in to github.com
                                      │             with “GitHub” in Chrome"  → Allow
browser ──starts──▶ 2Secret (as native messaging host) ◀── the login, once, over access.sock
                      │ stdin/stdout
                      ▼
                   2Secret extension: fills the sign-in page that is the active tab, submits it
                      │
                      ▼
                   the agent hears {"filled": true, "browser": "chrome", "submitted": true}
```

1. The agent calls `fill_login` with the item and the address of the sign-in
   page it has open. The item has to be a login for that website (matched
   like autofill: by registrable domain, `https` items never on `http` pages).
2. 2Secret asks you, with the same choices as for other requests (once, for
   this item until 2Secret locks, for 8 hours) and the optional biometric
   question. Nothing is asked when no browser is connected: the agent is told
   to have you set up the browser connection.
3. After *Allow*, the app hands the user name, password and the one-time code
   of that moment to the browser extension, through 2Secret's own native
   messaging host (see *Setting up the browser connection*). The extension
   fills the **active tab** whose address belongs to the item's website (the
   window used last first), in every frame that belongs to the website, and
   submits the form (unless the agent asked `submit: false`). It never fills a
   tab the agent names, a background tab or an incognito window. With several
   browsers (or profiles) connected, each gets one try until one has the tab.
4. The agent gets the outcome: filled (and submitted) in which browser, or why
   not: no open tab for the website, nothing to fill on the page, or no answer
   from the browser within 30 seconds. The password never reaches the agent.

Sign-in pages that ask for the user name and the password on separate steps
need `fill_login` twice; the second call fills the password (and a one-time
code when the page asks for one on a later step: call it again). Everything
is logged under *AI agents* as *fill in the browser*, and the browser itself
is listed there as an agent (`Chrome extension`), which you can revoke.

**What this does not protect against.** An agent that drives the browser can
read what was filled from the page before it is submitted (through the
browser's automation interface), so a fill is as good as handing it the
value for that one website; submitting right away keeps that window short.
It is still far better than giving the agent the password: nothing lands in
the conversation, and the agent cannot use the login anywhere else.

### Setting up the browser connection

1. Install the 2Secret extension in your browser (Chrome Web Store or Firefox
   Add-ons; see [EXTENSION.md](EXTENSION.md), also for an unpacked build).
2. In the desktop app: *Settings → Desktop app → AI agents → Turn on*, then
   *Browser connection → Set up for my browsers*. 2Secret writes a native
   messaging host manifest for every browser it finds on your computer:
   - macOS: `~/Library/Application Support/<Browser>/NativeMessagingHosts/io.github.joostiphone.twosecret.json`
     (Google/Chrome, Chromium, BraveSoftware/Brave-Browser, Microsoft Edge, Vivaldi, Arc/User Data)
     and `~/Library/Application Support/Mozilla/NativeMessagingHosts/` for Firefox;
   - Linux: `~/.config/<browser>/NativeMessagingHosts/` (google-chrome, chromium,
     BraveSoftware/Brave-Browser, microsoft-edge, vivaldi) and `~/.mozilla/native-messaging-hosts/`;
   - Windows: the manifests in the data folder under `native-host/`, with a
     registry value per browser under
     `HKEY_CURRENT_USER\Software\<Vendor>\NativeMessagingHosts\io.github.joostiphone.twosecret`.

   The manifest names 2Secret's own program as the host and allows only the
   2Secret extension (by its id). *Remove* deletes them again. At every start
   2Secret rewrites them for the copy that runs, so moving the app or an
   update needs nothing from you.
3. Restart the browser once. The extension then connects by itself whenever
   the browser runs; 2Secret asks the first time whether the browser may
   connect (it never reads your vault). *Browser connection* shows which
   browsers are set up and which are connected right now.

Things to know:

- The browser starts the host with the data folder of your user account;
  `TWOSECRET_HOME` set in a shell does not reach it. The app and the host have
  to use the same data folder.
- Browsers installed as a Snap or Flatpak (Ubuntu's default Firefox is a
  Snap) run in a sandbox that cannot start native messaging hosts, or only
  through the desktop portal. Use the distribution's package or the
  browser's own installer.
- A browser started with another profile folder (`--user-data-dir`) looks
  for the manifest in that folder (Chromium browsers) and does not find it.
- A development build of the extension has another id than the store build.
  Enter its id (from the browser's extensions page) under *Extension ids of
  development builds*; the store build is always allowed.
- Agent browsers that run their own Chromium (Playwright, Browser Use)
  have to load the extension in a persistent context and run on the same
  computer as the app.

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
| `fill_login` | yes | Sign the user in on a website in their own browser: 2Secret fills and submits the sign-in page that is the active tab; the model never sees the password |
| `agent_status` | no | Whether 2Secret is reachable, as which agent this connection is known, and which browsers are connected |

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
- A login filled in the browser can be read from the page by an agent that
  drives that browser, until the page is submitted. Let it submit (the
  default), and treat a fill as giving the agent that one login for that one
  website.
- Agent Access is off by default and only in the desktop apps (macOS,
  Windows, Linux). The web vault and the phone apps have no socket; the
  browser extension only receives the logins you allow, through the app.

See [docs/SECURITY.md](SECURITY.md) for the full picture.
