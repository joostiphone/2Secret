# 2Secret: notes for AI assistants

Read README.md and CONTRIBUTING.md first. `docs/AGENTS.md` explains how an
AI tool uses 2Secret itself (`2secret mcp`).

## Releasing

Follow CONTRIBUTING.md, *Releasing*. Every version needs
`ios/AppStore/testflight/en-US.txt` and `nl-NL.txt`: what is new in the build
and what testers should test. The Release workflow refuses a version without
them and puts them in TestFlight. When you prepare a release, also give the
owner the Dutch text (`nl-NL.txt`).
