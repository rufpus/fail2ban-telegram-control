# Third-party components

The MIT license in this repository applies to this project's own files.
Dependencies keep their respective licenses; no Fail2ban, nftables or Telegram
client source code is bundled here.

- **[Fail2ban](https://github.com/fail2ban/fail2ban)** is installed separately by
  Ubuntu. Its Python modules identify their license as GPL-2.0-or-later; see
  [Fail2ban's license](https://github.com/fail2ban/fail2ban/blob/1.0.2/COPYING).
  The integration imports the installed Fail2ban API at runtime. Its license
  is not replaced by this project's MIT license.
- **[nftables](https://netfilter.org/projects/nftables/)** is an external system
  dependency. This project invokes its command-line interface.
- **[Telegram Bot API](https://core.telegram.org/bots/api)** is an external
  service. No Telegram client code, logos or fonts are distributed. Demo images
  are generated examples, not screenshots of a real Telegram account.
- **[ipwho.is](https://ipwhois.io/documentation)** is an optional external IP
  geolocation service. No database is redistributed. This integration disables
  lookups by default.

When redistributing dependencies or a combined deployment, review their own
license and service requirements separately.
