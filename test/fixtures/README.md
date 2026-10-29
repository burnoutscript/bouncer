# Test fixtures

Everything in `npm-stealer`, `npm-obfuscated`, `npm-ai-hijack`, `pypi-dropper`, `pypi-pth`, `mcp-poisoned`, `skill-hidden` and `install.sh` is a **simulation** of a real attack pattern, written to test bouncer. None of it is real malware:

- every "exfiltration" target is an `.example` domain, which can never resolve
- every encoded payload decodes to `console.log('simulated payload')` or `print('simulated payload')`
- nothing here is published to any registry

`npm-clean` and `mcp-clean` are the honest counterparts and must always scan as SAFE.
