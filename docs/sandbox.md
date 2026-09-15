# Execution Isolation

KMN-CyberSeek has a capability gate for autonomous commands, but the default
launcher still executes approved tools on the host. `FULL_AUTO_MODE=true` is
therefore appropriate only inside a disposable, isolated lab network.

## Recommended Lab Boundary

Run the backend inside a disposable container or VM with:

- a dedicated Docker/VM network containing only the authorized target labs;
- no host filesystem mounts except a temporary workspace;
- read-only application image and a writable `/tmp` or artifact volume;
- `--cap-drop=ALL` plus only the network capabilities required by the scanner;
- `no-new-privileges`, a non-root application user, and resource limits;
- no cloud metadata route and no unrestricted internet egress;
- a separate API token and an allowlisted target CIDR.

Example container boundary (adapt the image and network to the lab):

```bash
docker run --rm --name kmn-cyberseek \
  --network pentest-lab \
  --cap-drop=ALL --cap-add=NET_RAW \
  --security-opt=no-new-privileges \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=512m \
  --pids-limit=256 --memory=4g --cpus=2 \
  -e FULL_AUTO_MODE=false \
  -e SCOPE_ALLOWLIST=192.168.100.0/24 \
  kmn-cyberseek:lab
```

Do not expose the backend beyond the lab operator network. Container isolation
does not replace authorization, scope validation, or the command capability gate.

## Capability Policy

Automated execution is denied for destructive host operations such as raw disk
writes, filesystem destruction, shutdown/reboot, fork bombs, bulk database
deletion, and download-and-execute chains. Operator-approved commands use a
separate reviewed path, but the target authorization and non-interactive checks
remain mandatory.

## Verification Boundary

The application distinguishes `suspected`, `attempted`, `verified`, and
`confirmed` evidence. A report must not call a target compromised solely because
a tool returned exit code zero or because target output contained words such as
`root`, `shell`, or `meterpreter`.
