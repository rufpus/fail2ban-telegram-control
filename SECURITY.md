# Security and privacy

## Trust model

The service runs as root and has `CAP_NET_ADMIN`. It can change SSH access.
Only the configured positive `user_id` in the matching private `chat_id` may
run commands or use buttons. Groups, additional operators, other jails,
arbitrary shell commands and mass unbanning are not supported.

Single-IP commands execute immediately. Subnet changes require a message-bound,
single-use confirmation with a two-minute expiry. Commands older than five
minutes are rejected after an outage. IP addresses and durations are parsed
strictly and are passed as structured arguments, not interpolated shell input.

The bot token and the owner's Telegram account authorize administration. Keep
them private. Rotate a leaked token using BotFather, update the server's
root-owned configuration and restart the service.

The service unit restricts writable paths and capabilities. This is still a
privileged administration tool; those restrictions do not make it unprivileged.

## Data destinations

- Telegram receives banned IPs, the configured server label, ban history and
  up to three matching log lines. Logs can contain SSH usernames and other
  security-related details. Use a dedicated private bot.
- With `geoip: true`, banned public IPs are also sent over HTTPS to `ipwho.is`.
  Tokens and log lines are not sent to that provider. Lookups are disabled by
  default; cached answers do not remove the provider's independent retention.
- SQLite stores history, pending messages, buttons, operation intents and audit
  records locally. These survive restarts. Events, audit records, expired geo cache and completed
  notifications have a default 30-day TTL (`F2BT_RETENTION_DAYS`); live bans and
  pending notifications are preserved. Backups have independent retention.
  Monitor disk use and protect backups.
- There is no project telemetry or analytics endpoint.

## Before opening an issue or sending screenshots

Remove tokens, SSH keys, real IPs, usernames, server labels, Telegram IDs, chat
contents and database files. Use documentation addresses such as
`203.0.113.42`. Do not upload `/etc/fail2ban-telegram-control/config.json` or
`/var/lib/fail2ban-telegram-control/`.

For a suspected vulnerability, use GitHub's **Report a vulnerability** option
if it is available. Otherwise open an issue containing only a request for a
private contact channel; do not post exploit details or secrets publicly.

## Compatibility boundary

Per-IP expiry changes use private APIs of Fail2ban **1.0.2**. The installer and
mutation bridge reject untested versions. Re-test compatibility before updating
Fail2ban or changing its firewall backend. Existing Fail2ban protection remains
independent of Telegram delivery.
