# Execution Isolation

## Shipped Default

**Local execution is unisolated host execution.** The scanner uses the policy
and backend boundary in `core/command_runner.py`; its default remains local.
`FULL_AUTO_MODE` does not select an execution backend or establish isolation.
Use autonomous execution only in an authorized disposable lab.

`BackendConfig()` explicitly defaults to `backend="local"`. The trusted operator
can explicitly select Docker with `KMN_EXECUTION_BACKEND=docker` via
`backend_config_from_env()`. `plan_execution()`
labels local plans `unisolated host execution` so callers can display the actual
boundary. `plan_command()` remains available to existing callers unchanged in
shape; it does not enforce scope or select a backend.

## Scope Checking

`check_command_scope(command, scope_allowlist)` returns a rejection string, or
`None` on success. Empty/unset scope retains the existing unrestricted mode.
A configured malformed list, including a comma-only list or empty entry, is
rejected, even for a local command. IP addresses, contained CIDR subnets, exact
DNS names, and `*.suffix` names are accepted scope entries. IPv4 and IPv6 are
kept separate. DNS comparisons ignore case and one terminal root dot;
wildcards match subdomains, not the apex or IP addresses. Zone-qualified IPv6,
malformed numeric IPs, and target ranges other than CIDR are rejected.

Scoped commands use small, explicit argument grammars rather than a search
for anything resembling a host. Every explicit positional/option destination
must pass scope authorization, including URL authorities, bracketed IPv6, and
proxies. These grammars support selected options for `nmap`, `ping`, `ping6`,
`traceroute`, `nc`, `ftp`, `curl`, `wget`, `smbclient`, `mysql`, and `redis-cli`.
The standalone `set RHOSTS`/related host-setting form is also understood.
This does not enable embedded Metasploit command programs under scope.

Unknown binaries, wrappers, interpreter bodies, shell composition/expansion,
unrecognized options, target files, scripts, redirects, and network commands
without explicit destinations fail closed. `wget` must explicitly specify
`--max-redirect=0`; redirect-following options in `curl` are not supported.
Use a literal positional Nmap target, not `nmap --host` (not a valid Nmap target
option). Supported options are intentionally narrower than each tool's CLI.
Adding a tool requires reviewing its full destination-changing argument syntax,
not merely adding its binary to a list.

Common hostless local utilities such as `echo`, `printf`, `ls`, `cat`, `head`,
`tail`, `wc`, `grep`, `id`, `whoami`, `pwd`, `uname`, and `date` remain usable.
General-purpose execution wrappers such as `env`, `find -exec`, and runtimes
are not considered hostless local utilities. This is a destination gate, not
host filesystem access control or a guarantee that a local command is harmless.

**Lexical scope validation is not a network firewall.** DNS names are not
resolved or pinned. DNS rebinding, tool defaults/configuration files, DNS
resolvers, proxies, redirects or secondary connections within a protocol can
change actual network traffic. Use trusted binaries, a controlled PATH, trusted
tool configuration, and external network enforcement. The existing local
launcher has no hard egress boundary just because `SCOPE_ALLOWLIST` is set.
Scoped executable paths are restricted to bare tool names or the standard
`/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/local/bin`, and
`/opt/homebrew/bin` directories. These directories and PATH must be trusted;
an arbitrary executable named like a supported tool is not safe.

## Optional Docker Backend

Configure this API only with trusted operator data, never model-generated
arguments or tool output. The image must already exist locally; image pulls are
disabled. Prefer an audited digest-pinned image without secrets, unexpected
startup configuration, proxy settings, or untrusted executables.

### Operator Environment

`backend_config_from_env(environment=None)` reads `os.environ` by default, or an
explicit trusted string mapping. It returns `BackendConfig` and raises
`ValueError` on invalid settings before execution. Scanner uses this loader
unless constructed with an explicit `BackendConfig`. Gateways should call the
same loader and pass its result to `execute_command()`; the execution/planning
APIs do not implicitly load backend settings when `config` is omitted.

| Variable | Default | Accepted Values |
| --- | --- | --- |
| `KMN_EXECUTION_BACKEND` | `local` | Exactly `local` or `docker` |
| `KMN_DOCKER_IMAGE` | Empty | Explicit preprovisioned image reference; required for Docker |
| `KMN_DOCKER_NETWORK` | `none` | `none` or a dedicated network name |
| `KMN_DOCKER_NETWORK_POLICY_ATTESTED` | `false` | Exactly lowercase `true` or `false` |
| `KMN_DOCKER_MEMORY_MB` | `512` | Positive decimal integer MiB |
| `KMN_DOCKER_CPUS` | `1.0` | Positive finite decimal number, optionally in exponent notation |
| `KMN_DOCKER_PIDS_LIMIT` | `64` | Positive decimal integer |

Only missing settings get defaults. Unknown/empty backends, malformed booleans,
invalid image/network values, and invalid resource limits fail closed; there
is no fallback to local on a configuration error. Supplied Docker settings are
validated even when the backend is local. Values are not whitespace-trimmed.
Image references use letters/digits and `_./:@-` and must start with a letter or
digit; network names use letters/digits and `_.-` and must start with a letter or
digit. `host`, `bridge`, `default`, and shared namespace selectors are rejected.
`KMN_EXECUTION_IMAGE`, `KMN_EXECUTION_NETWORK`, and similarly named alternatives
are not aliases and are not read. There are no environment overrides for the
Docker binary or environment allowlist in this loader.

Docker plans use a single argv command, override the image entrypoint with the
requested tool, and do not construct a shell string. Compound shell commands
are rejected even when autonomous shell composition was separately enabled.
No Docker socket, home directory, secret, workspace, or other host filesystem
mounts are added. There is no arbitrary Docker-options escape hatch.

The container uses UID/GID `65534:65534`, `--cap-drop=ALL`,
`no-new-privileges`, a read-only root, an isolated `/tmp` tmpfs with
`noexec,nosuid,nodev`, an init process, no published ports, and no persistent
Docker logging. Default limits are 512 MiB memory (no extra swap), one CPU,
64 PIDs, 1,024 file descriptors, and a 64 MiB tmpfs. Memory/CPU/PID limits are
configurable positive values. Raw socket scans and other operations requiring
extra capabilities will fail; this backend deliberately does not add privileges
to make them work. Use unprivileged supported modes such as Nmap `-sT`.

Environment inheritance is explicitly allowlisted. By default only `LANG`,
`LC_ALL`, and `TZ` are copied to a tool, with a controlled PATH for local
execution. HOME, API keys, proxy variables, runtime loader hooks, and Docker
connection settings are not inherited by default. The Docker client gets only
the controlled PATH, not the container's selected environment values. An
operator may customize `environment_allowlist`; do not use it for secrets or
variables that change tool destinations/startup behavior. Docker image ENV
values are part of the trusted image and are not stripped by this mechanism.
The host-side Docker client still needs access to its daemon; that access is
never mounted into the tool container. Docker daemon access is privileged and
belongs only in the trusted launcher.

## Network Attestation

**Docker alone does not enforce scope.** A named Docker bridge, including an
`internal` network, is not proof of per-scope egress enforcement. It may still
permit traffic to other containers, the host gateway, DNS, or unintended routes.
The backend does not provision, inspect, or verify a network policy.

Before scoped Docker execution, the operator must preconfigure a dedicated
isolated network and set both `network="<that-network>"` and
`network_policy_attested=True`. The flag is an explicit operator assertion that
external enforcement matches the exact scope being passed to this invocation.
It is not automatically discovered or a cryptographic proof. Do not reuse a
configuration with a different session scope unless its policy has been updated.
Missing attestation or network fails closed before any subprocess starts,
including for scoped hostless local commands.

The external policy must deny every destination except the authorized lab
targets, for both IPv4 and IPv6, including host/daemon addresses, cloud metadata,
other containers, arbitrary DNS, public internet, and alternate routes. Allow
only explicitly controlled name resolution as needed. Apply the boundary to
all protocol traffic, including proxy/redirect/secondary connections, and test
denials from inside the actual tool image. DNS-name scope needs a corresponding
controlled DNS/IP policy; lexical hostname matching does not create one.

`host`, `bridge`, `default`, and container/shared namespace selectors are
rejected. Without any scope, `network="none"` is the safe default and needs no
attestation. Any connected network still requires an explicit named network and
attestation. Scoped execution with `network="none"` is intentionally rejected
rather than presented as an enforced, usable scoped network.

## Integration API

The following is an integration example for an already-authorized gateway call
using explicit configuration (alternatively use `backend_config_from_env()`):

```python
from core.command_runner import BackendConfig, execute_command, plan_execution

sandbox = BackendConfig(
    backend="docker",
    image="kmn-tools:lab",  # Preprovisioned, audited image; prefer a digest.
    network="authorized-lab",  # Provision and enforce externally first.
    network_policy_attested=True,
)
scope = "192.168.100.0/24"
command = "nmap -sT -n -p 443 192.168.100.10"
plan = plan_execution(command, "ai_auto", config=sandbox, scope_allowlist=scope)
if plan.error:
    raise ValueError(plan.error)

# Inside the caller's async function, after its authorization/approval checks:
result = await execute_command(
    command, "ai_auto", config=sandbox, scope_allowlist=scope, timeout=60,
)
# result.returncode, result.stdout, result.stderr (raw output bytes)
```

`plan_execution()` is side-effect-free and exposes argv, backend, isolation,
environment, and any policy error. `execute_command()` replans, rejects policy
errors with `ValueError`, and returns `ExecutionResult`. Both accept an optional
source environment mapping and read `SCOPE_ALLOWLIST` if `scope_allowlist=None`;
passing `""` explicitly requests unrestricted scope. Autonomous modes
`ai_auto` and `playbook` retain binary, destructive-capability, and runtime gates.
Operator authorization and existing non-interactive/session checks are still
the gateway's responsibility. Do not execute a failed plan's argv directly.

`run_subprocess(argv, timeout=..., environment=..., cwd=...)` is a reusable
POSIX async argv helper for scanners. It closes stdin, captures output bytes,
starts a new session, and kills/reaps the process group on timeout or
cancellation, including cancellation during process startup. The output is
buffered, not streamed. This low-level helper does not authorize commands and
inherits the host environment if `environment=None`; use `execute_command()`
for the policy/backend boundary.

Timeouts raise `CommandTimeoutError`, a `TimeoutError` subclass also caught by
`asyncio.TimeoutError`. Its `stdout` and `stderr` attributes contain all partial
raw bytes captured after killing/reaping the process group. Scanner retains
these bytes as partial results rather than treating the scan as successful.
Cancellation propagates
`asyncio.CancelledError` after cleanup. Docker execution additionally performs
a bounded `docker rm --force` on its uniquely named container on every exit;
killing just the Docker client cannot stop a daemon-managed container. Cleanup
failures are surfaced, not reported as successful containment. A broken or
unreachable daemon requires operator intervention to verify/remove remaining
containers. Host process-group cleanup cannot contain descendants that escape
their session; use real isolation for untrusted code. The helper is POSIX-only.

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
