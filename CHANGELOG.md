# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- CodeQL and OpenSSF Scorecard workflows, and Dependabot updates for GitHub Actions.

### Changed
- GitHub Actions are pinned to full commit SHAs.
- SECURITY.md links the private reporting form and states the disclosure policy.
- `TELEGRAM_CHAT_ID` must be a private chat: a group or channel id is refused at startup.

### Security
- The gate denies tilde forms it does not expand (`~+`, `~-`, `~N`, `~name`) and zsh `=name`
  expansion, and treats more shell-set variables as dangerous to assign (`PWD`, `OLDPWD`,
  `DIRSTACK`, `NULLCMD`, `READNULLCMD`, `FPATH`, `BASH_*`, zsh parameter arrays).
- An unquoted heredoc with a body line ending in a backslash is denied.
- An input redirection, heredoc or here-string without a command is denied.
- Pattern expansion has a time budget, and the fixed folder in front of a pattern is judged
  before the pattern is expanded.
- A delete program with a recursive or force flag, passed to a program the gate does not know
  (as separate arguments or inside one quoted argument), is denied. Program names are matched
  case-insensitively when that makes them dangerous (`RM`, `CURL`).
- `git config` reads need an OK unless they are limited to `--local`, `--worktree` or `--file`;
  writes stay "never" in every scope.
- Git path operands are brace-expanded, and patterns are judged by the files they could select,
  so `git diff -- .en{v,x}` or `git diff -- '.e*'` cannot read a protected file. Pathspec magic
  (`:(icase)`, `:!`, `:/`) needs an OK.
- Approval summaries show invisible Unicode characters (bidi controls, zero-width marks).
- The listener also requires the sender id to be the owner's, for messages and buttons.
- Outbound redaction also covers API keys, bot tokens, JWTs, private keys, credentials inside
  URLs, social security numbers and more phone formats, also when glued to other text
  (`bot<token>` in a URL, `my_<key>`). It remains pattern-based and partial.
- The CodeQL workflow checks out without persisting credentials.

## [0.1.0] - 2026-09-30

### Added
- Initial public release.

[Unreleased]: https://github.com/decano5107-boop/sancho/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/decano5107-boop/sancho/releases/tag/v0.1.0
