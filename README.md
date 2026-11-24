# MON-PRX-SCRIPTS

Unified scripts for the MON-PRX Zabbix monitoring agents (integrit s.r.o.).
Only scripts that run on monitored machines live here. No templates, no customer data, no secrets.

- `windows/mon_prx_windows.*`        - Windows PCs (profile MON-PRX-WINDOWS)
- `windows/mon_prx_windows_server.*` - Windows Servers (profile MON-PRX-WINDOWS-SERVER)
- `manifest.json` - SHA-256 of every script; `manifest.sig` - RSA signature of the manifest
- `signing-public.xml` - public key the machines use to verify `manifest.sig`
- `tools/sign.py` - rebuilds manifest and signature (private key is kept outside this repository)

A machine replaces a script only when the manifest signature and the file checksum both match.
