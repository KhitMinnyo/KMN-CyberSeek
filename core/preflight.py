"""Offline readiness checks. Never contact a provider, Docker, or a target."""

import os
import shutil

from core.command_runner import backend_config_from_env, plan_execution
from core.validators import is_valid_target, is_target_in_scope


def evaluate_preflight(target, authorization_confirmed, scope_allowlist=None,
                       connector=None, scanner=None):
    """Evaluate configuration, not live availability; no network or subprocess.

    An injected scanner replaces the host nmap dependency unless it is the
    shipped Scanner. Docker image/tool availability needs external attestation.
    """
    checks = []

    def add(name, ready, required=True, detail=""):
        checks.append({"name": name, "ready": bool(ready), "required": required,
                       "status": "ready" if ready else ("blocked" if required else "warning"),
                       "detail": detail})

    valid = isinstance(target, str) and is_valid_target(target)
    scope = os.getenv("SCOPE_ALLOWLIST", "") if scope_allowlist is None else scope_allowlist
    add("target", valid)
    add("authorization", authorization_confirmed is True)
    add("scope", valid and is_target_in_scope(target, scope))
    from core.scanner import Scanner
    needs_nmap = scanner is None or isinstance(scanner, Scanner)
    docker_requested = os.getenv("KMN_EXECUTION_BACKEND", "local") == "docker"
    add("tool:nmap", bool(shutil.which("nmap")) if needs_nmap and not docker_requested else True,
        detail="Host nmap required" if needs_nmap else "Injected scanner owns tool readiness")
    if scanner is not None and isinstance(vars(scanner).get("ready"), bool):
        add("scanner", vars(scanner)["ready"])
    for tool in ("curl", "nikto", "gobuster", "msfconsole"):
        add("tool:" + tool, bool(shutil.which(tool)), required=False)
    backend = None
    try:
        config = backend_config_from_env()
        backend = config.backend
        plan = plan_execution("nmap -sV " + target if valid else "nmap", "manual",
                              config=config, scope_allowlist=scope)
        add("backend_plan", not plan.error, detail=plan.error or plan.isolation)
        if backend == "docker":
            add("tool:docker", bool(shutil.which(config.docker_binary)))
            add("docker_network", config.network != "none" and config.network_policy_attested,
                detail="A dedicated network with externally enforced scope egress must be attested")
            add("docker_tools", os.getenv("KMN_DOCKER_TOOLS_ATTESTED") == "true",
                detail="Preprovisioned image must attest nmap availability")
    except ValueError as exc:
        add("backend_plan", False, detail=str(exc))
    values = vars(connector) if connector is not None else {}
    effective = values.get("provider")
    from ai.connector import KMN_AI_Connector
    # The shipped connector can fall back during construction. Neither the
    # current environment nor its effective provider proves the original request.
    requested = (values.get("requested_provider") if isinstance(connector, KMN_AI_Connector)
                 else values.get("requested_provider") or effective)
    requested = {"api": "deepseek", "ollama": "local"}.get(requested, requested)
    provider_ready = effective in {"none", "local", "openai", "anthropic", "openrouter", "deepseek"} and requested == effective
    if effective in {"openai", "anthropic", "openrouter", "deepseek"}:
        provider_ready = provider_ready and bool(values.get("api_key"))
    if effective == "local":
        provider_ready = provider_ready and bool(values.get("ollama_url"))
    if effective != "none" and isinstance(values.get("ready"), bool):
        provider_ready = provider_ready and values["ready"]
    add("provider", provider_ready, detail=("Deterministic mode; model calls disabled" if effective == requested == "none"
                                            else "Configuration readiness only; connectivity not probed"))
    return {"version": 1, "ready": all(c["ready"] for c in checks if c["required"]),
            "checks": checks, "backend": backend,
            "provider": {"requested": requested, "effective": effective, "ready": bool(provider_ready)}}
