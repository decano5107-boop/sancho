# Architecture and threat model

Sancho lets you drive Claude Code on your own Mac from your phone. The hard part is not the
messaging; it is that an agent with shell access is now reachable from a chat app. Everything
below is organised around one question: **what stops a message, a file, or a web page from
making the agent do something you did not approve?**

## Why build on Claude Code itself

The engine is `claude -p --resume`, the same Claude Code you use at the desk. That means the
assistant loads your skills, MCP servers, hooks and project memory with no second stack to
maintain, and adds no new network surface: no gateway, no listening port, no plugin
marketplace. The only new code is the front door (the listener) and the gate.

## Components

```
 phone ──Telegram Bot API (outbound long-poll only)──▶ listener
                                                          │  your chat only · your own text or voice
                                                          ▼
                                                        router    /p <project>  → working dir, thread
                                                          │
                                                          ▼
                                                        runner    claude -p --resume <session>
                                                          │
                              ┌───────────────────────────┴───────────────────────────┐
                              ▼                                                       ▼
                        PreToolUse gate  ── free ──▶ tools (Bash, Read, MCP)    Claude Code's own
                        free / needs OK / never                                 permission allowlist
                              │ needs OK                                        (second net)
                              ▼
                        held call + one-time code ──(listener)──▶ phone ──"OK 7F3A"──▶ that one call, once
                                                          │
                                                          ▼
                                                        outbound  PII scrub · tables flattened · short first
                                                          │
                                                          ▼
                                                        phone
```

Terms used below:

- **Thread**: one Claude Code session per project, resumed on each message and rotated after a
  period of inactivity or a number of turns.
- **State directory**: where Sancho keeps its runtime state (threads, the Telegram offset, held
  calls, the full text of long replies); `~/.sancho/state` by default.
- **Allowed folders, hosts and safe scripts**: lists in `config.json`, section `gate`. Nothing
  outside the allowed folders is reachable, except a scratch folder in the system temp
  directory.

## 1. The front door

In order, for every update:

1. **Only you, in your private chat.** A message is dropped silently unless both its chat id
   and its sender id equal `TELEGRAM_CHAT_ID`. A group chat id is refused at startup: in a
   group, every member could write to the bot and approve its actions.
2. **Only your own words.** A forward (`forward_origin`, `is_automatic_forward`), a quote or
   reply that carries someone else's text (`external_reply`, `quote`, a `reply_to_message`
   whose author is neither you nor the bot) and a message sent via another bot (`via_bot`) are
   rejected with a notice. This closes the easiest prompt-injection route: "forward this to
   your assistant".
3. **No attachments.** Documents, photos, videos and stickers are rejected with a notice.
4. **Voice only if it is yours.** A voice note that is not forwarded is transcribed locally
   and treated as text.
5. **Buttons** (approve, reject, more) pass the same chat and sender check.

## 2. The gate: three tiers, enforced in code

One `PreToolUse` hook classifies every **tool call** — never the conversation. It does not
matter what a document or a web page says; what matters is what the model then tries to do.

| Tier | What falls in it | What happens |
|---|---|---|
| **free** | Reading and searching inside allowed folders; web search (configurable); an explicit allowlist of read-only commands **and flags**, and read-only git subcommands | Runs |
| **needs OK** | Writing or editing inside allowed folders; fetching a URL; commits and pushes; moving files; running any script or binary that is not on the safe list; sending mail or calendar invites through MCP tools | Held until you approve it from the phone |
| **never** | Recursive or forced deletes; any access to secrets (`.env`, `~/.ssh`, `~/.aws`, `~/.claude`, the Keychain); any access to Sancho's own code, configuration and state directory; printing the environment or a variable; inline interpreter code (`python -c`, `node -e`) and wrappers that hide a command (`bash -c`, `eval`); network tools to hosts not on the list; anything the parser cannot read | Denied, with the reason |

Rules that make the tiers hold:

- **Denied paths win over allowed folders**, and a path is judged by where it really is, so a
  symlink planted inside an allowed folder cannot reach `~/.ssh`.
- **A chained command takes the highest tier of its parts.** `ls && rm -rf x` is "never".
- **Read-only by flag, not by name.** `find` is free; `find -delete`, `find -exec`, `sed -i`,
  `sort -o`, `git -c …` and any output redirection are not.
- **Sancho cannot touch Sancho.** Its code, its configuration and its state directory are
  "never" for every tool, so the model can neither read a held call nor edit the policy.
- **Unparseable means denied, and so does a crash.** Claude Code lets a tool call through when
  a hook crashes, so the gate catches every error itself and answers "deny".
- **Fetch is held, search is a documented trade-off.** A fetched URL goes to a host the *model*
  chose, which is an exfiltration channel, so it needs your OK. A search query can also carry
  data out, at far lower bandwidth; it is free by default for usability and can be moved to
  "needs OK" in `config.json`.
- **The gate only runs for Sancho's own child process** (it is injected with `--settings` and
  switched on by an environment variable), so it never interferes with your desk sessions.

**Second net.** The runner also pre-approves exactly the free tier in Claude Code's own
permission system and runs in a mode that refuses, rather than prompts for, anything not
pre-approved (nobody is at the desk to answer a prompt). If the gate were bypassed, Claude
Code's own permissions would still refuse the rest. One caveat: the gate's settings are merged
with your own Claude Code settings, so a broad allow rule in your own settings would widen this
second net.

## 3. The OK flow

1. The gate stores the held call — tool, input, a hash of both, the thread, the time — with
   two identifiers: a public reference and a secret four-character code. It denies the call
   with `HELD_FOR_APPROVAL <reference> — <summary>`. The model sees the reference, never the
   code.
2. The listener reads the held call from disk and sends you the summary, the code and
   **Approve** / **Reject** buttons. The summary is built by the gate from the call itself —
   the full command, path or URL — never from a description the model wrote; a long command is
   sent in full, so a harmless beginning cannot hide what follows.
3. Your approval (the button, or `OK <code>`) is checked: the code exists, it is unexpired, it
   belongs to this thread, it has not been used. The record is marked approved.
4. A **separate** run of the same thread starts. The gate allows the one call whose hash matches
   the approved record, once, and deletes the record.

The model never sees the code, cannot read the held records, and has no way to send a message
from your chat; a replayed or edited call does not match the hash.

## 4. The way out

Every reply passes through the same contract before it reaches the phone: known formats of
secrets and personal data are redacted; tables are flattened into lines a phone can read; the
first lines go out and the rest waits behind a **More** button.

The redaction is pattern-based and partial, a second net rather than a guarantee. It covers
credentials inside URLs, private key blocks, common API key and token formats (LLM, code-hosting, cloud, payment, chat-bot, mail and package-registry keys, JWTs), emails, phone numbers, US social security numbers, card-like numbers and long numeric ids, plus your own patterns (`outbound.scrub_patterns`). A secret in a format it does not know
(a custom token, a password in prose) passes through as written. The control that matters is
the gate, which keeps secret files and the environment away from the model in the first
place.

## Threat model

| Threat | Control |
|---|---|
| Someone else writes to the bot | Chat-id and sender-id check; group chats refused; the bot answers only you |
| A forwarded message carries instructions | Forwards rejected at the door |
| A file, log, web page or MCP result says "delete X" or "send this to…" | The gate classifies the call, not the text; deletes and exfiltration are "never"; everything else that changes state needs your OK |
| The model is talked into printing secrets | Secrets paths and environment printing are "never"; harness allowlist as second net |
| Personal data or a secret leaks to the phone | Secret paths and environment are "never" in the gate; pattern-based outbound redaction on every reply as a partial second net |
| A bug in the gate | The gate turns its own errors into a denial; Claude Code's permission allowlist still applies |
| Runaway cost or a loop | Per-query timeout, thread rotation, daily query alert |
| The Mac is exposed to the internet | Outbound long-poll only: no open port, no webhook, no tunnel |
| A stolen bot token | Revoke it with BotFather. The holder could read replies, but cannot approve anything: approvals are accepted only from your own account in your private chat. Secrets never enter git |

## What this does not protect against

- A command the gate classifies correctly but you approve without reading. The summary is
  short on purpose; read it.
- Code inside a script you have listed as safe. Listing a script trusts everything it does.
- A compromised Mac or Telegram account. Sancho assumes both are yours.
- What Telegram and the model provider see. Replies are redacted before they reach the phone,
  but Telegram stores bot chats on its servers, and the model provider processes the whole
  conversation.
