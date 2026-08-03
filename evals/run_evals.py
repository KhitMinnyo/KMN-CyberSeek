#!/usr/bin/env python3
"""
KMN-CyberSeek AI Reasoning Eval Harness
=======================================

Measures the QUALITY of the AI's next-step decisions against fixed engagement
scenarios and methodology rules — so a change to ai/prompts.py can be judged by a
score delta instead of a vibe. Because the model is stochastic, each scenario can
be run several times and the harness reports the mean score and variance.

Usage
-----
    # Score against the configured provider (DeepSeek API or local Ollama):
    python3 evals/run_evals.py --runs 3

    # Validate the harness/scoring itself offline (no model needed):
    python3 evals/run_evals.py --selfcheck

Exit codes: 0 = ran (or self-check ok); 2 = no provider configured; 1 = harness error.

The harness reuses the real KMN_AI_Connector, so it exercises the exact prompt and
parsing path the live loop uses.
"""

import argparse
import asyncio
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evals.scenarios import SCENARIOS


def score_decision(decision, checks):
    """Return (passed, total, failed_labels) for one decision."""
    passed, failed = 0, []
    for label, predicate in checks:
        try:
            ok = bool(predicate(decision))
        except Exception:
            ok = False
        if ok:
            passed += 1
        else:
            failed.append(label)
    return passed, len(checks), failed


# ── provider path ─────────────────────────────────────────────────────────────

async def _decide(connector, scenario):
    resp = await connector.ask_ai_async(
        scenario["context"], memory=scenario.get("memory")
    )
    # AIResponse -> plain dict for the rules
    return {
        "reasoning": getattr(resp, "reasoning", ""),
        "suggested_command": getattr(resp, "suggested_command", ""),
        "risk_level": getattr(resp, "risk_level", ""),
        "attack_phase": getattr(resp, "attack_phase", ""),
        "confidence": getattr(resp, "confidence", 0.0),
    }


async def run_provider(runs):
    try:
        from ai.connector import KMN_AI_Connector
    except Exception as e:
        print(f"[error] cannot import connector (install requirements.txt?): {e}")
        return 1

    connector = KMN_AI_Connector()
    if connector.provider == "api" and not connector.api_key:
        print("[skip] No DeepSeek API key and provider is 'api'. "
              "Set DEEPSEEK_API_KEY or configure local Ollama, then re-run.")
        return 2

    print(f"Provider: {connector.provider} | runs per scenario: {runs}\n")
    scenario_means = []
    for sc in SCENARIOS:
        run_scores, all_failed = [], []
        for _ in range(runs):
            try:
                decision = await _decide(connector, sc)
            except Exception as e:
                print(f"  [{sc['name']}] provider error: {e}")
                run_scores.append(0.0)
                continue
            passed, total, failed = score_decision(decision, sc["checks"])
            run_scores.append(passed / total if total else 0.0)
            all_failed.extend(failed)
        mean = statistics.mean(run_scores) if run_scores else 0.0
        var = statistics.pvariance(run_scores) if len(run_scores) > 1 else 0.0
        scenario_means.append(mean)
        flag = "OK " if mean >= 0.99 else ("~  " if mean >= 0.5 else "XX ")
        detail = ""
        if all_failed:
            # show the most common failed checks
            uniq = sorted(set(all_failed))
            detail = f"  failed: {', '.join(uniq)}"
        print(f"  {flag}{sc['name']:<34} mean={mean:5.2f} var={var:5.3f}{detail}")

    overall = statistics.mean(scenario_means) if scenario_means else 0.0
    print(f"\n{'=' * 64}\nOVERALL REASONING SCORE: {overall:.2%}  "
          f"({len(SCENARIOS)} scenarios x {runs} runs)")
    return 0


# ── offline self-check ────────────────────────────────────────────────────────

_GOOD = {
    "web_fingerprint_before_cms": {"suggested_command": "whatweb -a 3 http://10.0.0.10", "attack_phase": "enumeration", "reasoning": "fingerprint first"},
    "wordpress_wpscan_batch": {"suggested_command": "wpscan --url http://10.0.0.10 --batch --enumerate u,vp", "attack_phase": "enumeration", "reasoning": "wp confirmed"},
    "no_blind_repeat_of_nmap": {"suggested_command": "whatweb http://10.0.0.10", "attack_phase": "enumeration", "reasoning": "http not yet tested"},
    "credential_reuse_priority": {"suggested_command": "crackmapexec smb 10.0.0.10 -u admin -p 'Summer2024!'", "attack_phase": "credential_reuse", "reasoning": "reuse ftp creds"},
    "domain_uses_hostname_not_ip": {"suggested_command": "nuclei -u https://shop.example.com -severity high", "attack_phase": "enumeration", "reasoning": "use vhost"},
}
_BAD = {
    "web_fingerprint_before_cms": {"suggested_command": "wpscan --url http://10.0.0.10", "attack_phase": "enumeration", "reasoning": "guess wp"},
    "wordpress_wpscan_batch": {"suggested_command": "wpscan --url http://10.0.0.10", "attack_phase": "enumeration", "reasoning": "no batch"},
    "no_blind_repeat_of_nmap": {"suggested_command": "nmap -sV -sC -p- --min-rate 5000 10.0.0.10", "attack_phase": "enumeration", "reasoning": "repeat"},
    "credential_reuse_priority": {"suggested_command": "nmap -p- 10.0.0.10", "attack_phase": "reconnaissance", "reasoning": "ignore creds"},
    "domain_uses_hostname_not_ip": {"suggested_command": "nuclei -u https://10.0.0.10", "attack_phase": "enumeration", "reasoning": "used ip"},
}


def run_selfcheck():
    """Verify the rules discriminate: a 'good' answer should score ~1.0 and a
    'bad' answer clearly lower, for every scenario. No model required."""
    ok = True
    print("Self-check (offline) — good answers should score high, bad answers low:\n")
    for sc in SCENARIOS:
        gp, gt, _ = score_decision(_GOOD[sc["name"]], sc["checks"])
        bp, bt, bf = score_decision(_BAD[sc["name"]], sc["checks"])
        g, b = gp / gt, bp / bt
        good_ok = g >= 0.99
        discriminates = g > b
        status = "OK " if (good_ok and discriminates) else "XX "
        if not (good_ok and discriminates):
            ok = False
        print(f"  {status}{sc['name']:<34} good={g:4.2f}  bad={b:4.2f}  (bad missed: {', '.join(bf) or '-'})")
    print(f"\n{'=' * 64}\nSELF-CHECK {'PASSED' if ok else 'FAILED'}")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="KMN-CyberSeek AI reasoning evals")
    ap.add_argument("--runs", type=int, default=3, help="runs per scenario (provider mode)")
    ap.add_argument("--selfcheck", action="store_true", help="validate scoring rules offline")
    args = ap.parse_args()

    if args.selfcheck:
        return run_selfcheck()
    return asyncio.run(run_provider(args.runs))


if __name__ == "__main__":
    raise SystemExit(main())
