# Security

unbraid handles VPN credentials and decides where every connection goes, so security reports matter a lot here.

## Reporting a problem

Please don't open a public issue for a security problem. Report it privately through this repository's Security tab
(Report a vulnerability). Describe what you found, which version you tested (`unbraid --version`, or Settings, About &
support), your distribution and, if you can, the steps to reproduce it. You'll get a reply within a few days.

Please give a reasonable amount of time for a fix before you publish details. Fixed issues are mentioned in the release
notes.

## What counts

Anything that could expose a user's traffic, DNS lookups, credentials or keys. Some examples: a program reaching the
internet outside its chosen route, a leak while unbraid connects or reconnects, secrets written to disk or logs
unencrypted, another user on the computer reaching or changing someone's connection through the engine's socket, or the
engine (which runs as root) doing anything for a config beyond networking.

Problems in sing-box itself are best reported to the [sing-box project](https://github.com/SagerNet/sing-box). If you're
not sure where a problem belongs, send it here.

## Supported versions

Only the latest release gets security fixes.
