# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's private reporting:
**Security → Report a vulnerability** on this repository
(<https://github.com/paimonsoror/telltaledns/security/advisories/new>).

Tell us what you found, which version it affects (`telltale --version`), and how to reproduce it.
Only the maintainers can see the report. We will acknowledge it, work on a fix with you in that
private conversation, and agree a time to publish. We credit reporters in the release notes unless
they ask us not to.

## Supported versions

The latest stable release and the `edge` build of `main`. Fixes go to `main` first and ship in the
next release; a serious problem gets a patch release of the latest stable line.

## Scope

TelltaleDNS itself: the resolver, the web UI and API, the cluster protocol, the installer and the
container image. A problem in a third-party dependency is best reported to that project too; tell
us if it affects us.
