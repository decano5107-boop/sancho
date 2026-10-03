# Sancho

[![tests](https://github.com/decano5107-boop/sancho/actions/workflows/tests.yml/badge.svg)](https://github.com/decano5107-boop/sancho/actions/workflows/tests.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Drive Claude Code on your own Mac from your phone, behind a permission gate that decides in code.**

Sancho is a Telegram front end for the `claude` CLI. You message it; it runs Claude Code in the
project you picked, with your skills, MCP servers and memory, and answers on the phone. The hard
part is not the messaging: it is that an agent with shell access is now reachable from a chat
app. So every tool call passes through a gate with three tiers:

| Tier | Examples | What happens |
|---|---|---|
| **free** | Reading and searching inside your allowed folders; `ls`, `grep`, `git log` | Runs |
| **needs OK** | Writing a file, fetching a URL, `git commit`, running a script, sending an email | Held; you get the exact action and a one-time code on the phone |
| **never** | Recursive or forced deletes, and any delete outside a scratch folder; secrets (`.env`, `~/.ssh`, the Keychain); printing the environment; inline interpreter code; shell network commands to hosts not on your list; Sancho's own files | Refused, even if you would approve |

The approval code goes to your phone and never to the model, and it unlocks exactly the call
you saw, once. Nothing a document or a web page says can widen the gate, because the gate
judges the call, not the conversation. The full design and threat model are in
[docs/architecture.md](docs/architecture.md).

## What it does

- **One thread per project.** `/p <name>` picks a project folder; the conversation continues
  there until you switch, and starts fresh after a day of inactivity or 40 turns.
- **Approvals from the phone.** Held actions arrive with the full command or path, the code, and
  Approve / Reject buttons.
- **Only your own words get in.** Messages from other chats are ignored; forwards, quotes of other
  people and messages via other bots are refused.
- **Replies built for a phone.** Known formats of secrets and personal data are redacted, tables
  are flattened, long answers arrive in short form with a **More** button.
- **Optional extras**, each working only if its dependency is installed:
  - voice notes in (local Whisper) and voice replies out (local text-to-speech), `/voice on`;
  - charts drawn from a JSON spec the model writes, sent as images;
  - `/recall <words>`: full-text search over your past Claude Code sessions, run locally and
    without the model.

## Requirements

- macOS, Python 3.11 or newer (check `python3 --version`; the one that ships with the Xcode
  tools can be older), and the [Claude Code](https://code.claude.com) CLI.
- A Telegram bot of your own, created with [@BotFather](https://t.me/BotFather) and used only for
  this.
- Optional: `ffmpeg`, `mlx-whisper` and `pocket-tts` for voice (`pip install mlx-whisper
  pocket-tts`, `brew install ffmpeg`); `matplotlib` for charts.

## Set up

```bash
git clone https://github.com/decano5107-boop/sancho.git
cd sancho
cp .env.example .env
cp config.example.json config.json
```

1. **Bot token.** Put the token from BotFather in `.env` as `TELEGRAM_BOT_TOKEN`.
2. **Your chat id.** Open your bot in Telegram, press **Start** and send it any message. Then open
   `https://api.telegram.org/bot<token>/getUpdates` in a browser and copy
   `result[0].message.chat.id` into `.env` as `TELEGRAM_CHAT_ID`. If the result is empty, send
   another message and reload. It must be your private chat with the bot (a positive number,
   equal to your own user id): a group id is refused at startup, since every member of a group
   could approve actions.
3. **Claude Code token.** Run `claude setup-token` and put the result in `.env` as
   `CLAUDE_CODE_OAUTH_TOKEN`. It lets the headless `claude -p` use your subscription.
4. **Folders.** In `config.json`, set `gate.allowed_roots` to the folders the assistant may reach
   and `projects.roots` to where your projects live. Outside the allowed folders, only a scratch
   folder in the system temp directory is reachable. The gate's keys are documented in
   `sancho/tiers.py` (and the approval window, `gate.ok_ttl_minutes`, in `sancho/pending.py`);
   the others in the module that reads them. Setting `gate.denied_globs` replaces the built-in
   list; to add to it, use `gate.extra_denied`.
5. **Try it:** `python3 -m sancho.listener`, then message the bot `/help`.
6. **Keep it running.** Stop the step-5 process first (Ctrl-C: only one listener runs at a time),
   then `deploy/install.sh` installs it as a launchd agent that starts at login and restarts if
   it exits. Logs go to `~/.sancho/state/logs`, runtime state to `~/.sancho/state`.
   `deploy/install.sh --remove` undoes it.

## Commands

| Command | |
|---|---|
| `/p <name> [question]` | Pick the project (and optionally ask right away) |
| `OK <code>` / `/reject <code>` | Approve or refuse a held action (or use the buttons) |
| `/more` | The rest of the last long answer |
| `/new` | Start a clean thread in this project |
| `/status` · `/cancel` | What is running · stop it |
| `/recall <words>` | Search past sessions |
| `/voice on\|off` | Spoken replies |

Anything else is sent to Claude Code.

## Tests

```bash
python3 -m unittest discover -s tests
```

The gate's tests are derived from the threat model: deletes in every spelling, exfiltration through
the shell and the fetch tool, symlinks that escape an allowed folder, flags that turn a read into a
write (`find -delete`, `sed -i`), wrappers and chained commands, and replayed, expired or
edited approvals. The whole loop has also been run against the real `claude` CLI: a read ran
freely, a file write was held until approved and then ran once, and `printenv` was refused.

## Limits

- **It is a gate, not a sandbox.** It judges each call before it runs; code inside a script you
  mark as safe, or a program configured by a repository you open (a malicious `.git/config`, for
  instance), is trusted as a whole.
- **Your own Claude Code settings still apply.** The gate is added to your settings for Sancho's
  process only, but it is merged with them: a broad allow rule in your own settings widens the
  second line of defence (Claude Code's permission allowlist). The gate itself still sees every
  call first.
- **Telegram and the model provider see the conversation.** Telegram stores bot chats on its
  servers.
- **Outbound redaction is pattern-based and partial.** It covers credentials inside URLs, private key blocks, common API key and token formats (LLM, code-hosting, cloud, payment, chat-bot, mail and package-registry keys, JWTs), emails, phone numbers, US social security numbers, card-like numbers and long numeric ids, plus your own patterns
  (`outbound.scrub_patterns`). A token in a format it does not know reaches the phone as written:
  the gate keeping secrets away from the model is the real control.
- **Reading is free inside the allowed folders.** Keep private material outside them, or list it
  under `gate.extra_denied`. That includes git history: a secret that was ever committed is
  readable through `git show` or `git log -p`, whatever the path rules say.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
