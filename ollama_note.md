# Ollama Model Guide for KMN-CyberSeek

## What the AI needs to do well

KMN-CyberSeek depends on the model for three things, in order of importance:

1. **Structured JSON output** — every AI response must be valid JSON (`reasoning`, `suggested_command`, `risk_level`, `attack_phase`, `confidence`). A model that garbles this causes parse failures and halts the session.
2. **Multi-step reasoning** — the model must plan a full attack chain (OSINT → Recon → Enum → Exploitation → Priv-Esc), not jump to the end in 3 commands.
3. **Security command vocabulary** — knows nmap flags, metasploit modules, CVE identifiers, GlassFish/Tomcat/SMB quirks, etc.

---

## DeepHat vs qwen2.5 — which one for this project?

### DeepHat V1-7B

- **Base**: Qwen2.5-Coder-7B fine-tuned on cybersecurity data
- **Parameters**: 7.61B
- **Context**: 32,768 tokens default (131,072 with YaRN config)
- **License**: Apache-2.0 + DeepHat extension (NOT fully uncensored — still has usage restrictions)
- **Ollama**: `ollama pull deephat` (community GGUF quantizations available)

Strengths:
- Security-domain vocabulary is excellent out of the box
- Understands CVE identifiers, exploit frameworks, red-team terminology natively
- Smaller footprint — runs fast on limited hardware

Weaknesses:
- 7B = weaker multi-step reasoning — prone to stage-skipping (runs recon once, declares done)
- JSON compliance inconsistent — contributes to parse errors that halt the session
- No genuine improvement over base qwen2.5-coder-7b for structured output tasks

### qwen2.5:14b

- **Base**: Qwen2.5 14B (Alibaba QWEN team)
- **Parameters**: 14.7B
- **Context**: 32,768 tokens (standard Ollama pull)
- **License**: Apache-2.0

Strengths:
- 2x the parameters of DeepHat → significantly better JSON reliability
- Better multi-step reasoning → fewer stage-skip bugs
- Understands security commands well (Qwen2.5 was trained on code + technical text)
- More resistant to hallucinating progress it hasn't made

Weaknesses:
- Not cybersecurity-specialized (general model)
- Requires more RAM (~9GB for Q4)

### Verdict for KMN-CyberSeek

**Use qwen2.5:14b as primary.**

The #1 cause of session failures in this project is bad JSON output and premature stage advancement — both are model-reasoning problems, not vocabulary problems. A larger general model fixes both more reliably than a smaller specialized one. DeepHat's security vocabulary advantage does not compensate for its weaker reasoning at 7B.

Use DeepHat only if you are RAM-constrained to ≤ 12GB and cannot run a 14B model.

---

## Hardware-specific recommendations

### M2 Mac Mini — 24GB RAM (current)

| Priority | Model | Size on disk | Context | RAM usage |
|----------|-------|-------------|---------|-----------|
| ✅ Recommended | `qwen2.5:14b` | ~9 GB | 32,768 | ~11 GB |
| Alternative | `deepseek-r1:14b` | ~9 GB | 32,768 | ~11 GB |
| Stretch | `qwen2.5:32b` | ~19 GB | 32,768 | ~21 GB |
| Fallback | `deephat` / `qwen2.5:7b` | ~5 GB | 32,768 | ~6 GB |

**Settings → AI Configuration:**
- Model: `qwen2.5:14b`
- Context window: `32768`

```bash
ollama pull qwen2.5:14b
```

### M4 Pro — 64GB RAM (upcoming)

| Priority | Model | Size on disk | Context | RAM usage |
|----------|-------|-------------|---------|-----------|
| ✅ Recommended | `qwen2.5:72b` | ~42 GB | 131,072 | ~45 GB |
| Alternative | `deepseek-r1:70b` | ~40 GB | 32,768 | ~42 GB |
| Lighter option | `qwen2.5:32b` | ~19 GB | 65,536 | ~21 GB |

**Settings → AI Configuration:**
- Model: `qwen2.5:72b`
- Context window: `65536` (or `131072` if session history is long)

```bash
ollama pull qwen2.5:72b
```

With a 72B model at 131k context, the AI holds the entire session history in memory — stage regression, repeated commands, and context overflow effectively disappear as problems.

---

## Context window — why it matters

Local models have a fixed context window. When the session's conversation history exceeds it, the model silently forgets the oldest content — leading to:

- Repeated commands (forgot it already tried that)
- Stage regression (forgot it was in exploitation, goes back to recon)
- Hallucinated progress (confused about what has actually run)

KMN-CyberSeek has two built-in mitigations:

1. **Episode summaries** — every N commands, old history is compressed into a summary and re-injected. Configured via `EPISODE_SIZE` env var.
2. **Configurable context window** — Settings → AI Configuration → Context window (num_ctx). This directly tells Ollama how much to load into VRAM/unified memory.

Practical rule of thumb:

| Model size | Safe context (fits on device) |
|-----------|------------------------------|
| 7–8B | 16,384 |
| 13–14B | 32,768 |
| 32B | 32,768–65,536 |
| 70–72B | 65,536–131,072 |

---

## Quick setup commands

```bash
# M2 24GB — recommended setup
ollama pull qwen2.5:14b

# M4 Pro 64GB — recommended setup
ollama pull qwen2.5:72b

# Verify model is loaded and running
ollama list
ollama ps

# Switch model in Settings UI
# Settings → AI Configuration → Select model → Save
```

---

## Signs the model is struggling (and what to do)

| Symptom | Cause | Fix |
|---------|-------|-----|
| `echo 'AI response parsing error'` in command log | JSON parse failure | Switch to larger model or increase context window |
| Same command repeated 3+ times | Context overflow — model forgot it ran it | Increase context window |
| All stages "Done" after 5 commands | Weak reasoning — AI skipped phases | Switch to 14B+ model |
| Session stuck at 5% progress | Strategist not updating | Wait for command #5/10/15; or Reset AI |
| Session fails at "Credential Reuse" immediately | AI jumping stages | Stage gate fix is in place — update and restart |
