# MON-PRX-SCRIPTS

Unified scripts for the MON-PRX Zabbix monitoring agents (integrit s.r.o.).
Only scripts that run on monitored machines live here. No templates, no customer data, no secrets.

- `windows/mon_prx_windows.*`        - Windows PCs (profile MON-PRX-WINDOWS)
- `windows/mon_prx_windows_server.*` - Windows Servers (profile MON-PRX-WINDOWS-SERVER)
- `windows/mon_prx_update.ps1`        - daily self-update task on every Windows server (verifies the signature, then replaces own files); Windows PCs do not self-update
- `windows/mon_prx_actions.ps1/.json`  - server actions: read-only diagnostics, and start of STOPPED services listed per host in the signed json (max 3 per hour)
- `manifest.json` - SHA-256 of every script; `manifest.sig` - RSA signature of the manifest
- `signing-public.xml` - public key the machines use to verify `manifest.sig`
- `tools/sign.py` - rebuilds manifest and signature (private key is kept outside this repository)

A machine replaces a script only when the manifest signature and the file checksum both match.
