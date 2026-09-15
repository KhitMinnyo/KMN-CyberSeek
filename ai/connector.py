"""KMN-CyberSeek AI Connector Module.

Supports local Ollama plus DeepSeek, OpenAI/ChatGPT, Anthropic Claude, and
OpenRouter cloud APIs through one normalized response schema.
"""

import json
import logging
import os
import re
from typing import Dict, List, Optional, Any

from dotenv import load_dotenv
# Force reload environment variables to ensure fresh values
load_dotenv(override=True)

import httpx
import requests
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

API_PROVIDERS = {"deepseek", "openai", "anthropic", "openrouter"}
PROVIDER_ALIASES = {
    "api": "deepseek", "chatgpt": "openai", "claude": "anthropic",
    "open-router": "openrouter", "ollama": "local",
}


def _extract_json(text: str) -> Optional[dict]:
    """Extract the first valid JSON object from arbitrary AI output.

    Handles the common failure modes where a model wraps its JSON in markdown
    code fences, adds a preamble sentence, or emits thinking tokens before the
    actual response.

    Returns the parsed dict, or None if no valid JSON object was found.
    """
    if not text:
        return None

    # 1. Strip markdown fences (```json ... ``` or ``` ... ```)
    stripped = re.sub(r'```(?:json)?\s*(.*?)\s*```', r'\1', text, flags=re.DOTALL).strip()

    # 2. Try the stripped text first (clean path)
    for candidate in (stripped, text):
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

    # 3. Find the outermost {...} by scanning brace depth — handles preamble text
    #    and models that emit a sentence before the JSON blob.
    start = text.find('{')
    if start == -1:
        return None
    depth = 0
    for i, ch in enumerate(text[start:], start):
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start:i + 1])
                except json.JSONDecodeError:
                    break  # malformed even after extraction — give up

    return None


class AIResponse(BaseModel):
    """Standardized AI response format."""
    reasoning: str = Field(..., description="AI's thought process and analysis")
    suggested_command: str = Field(..., description="Command to execute")
    risk_level: str = Field(..., description="low/medium/high risk classification")
    target_info: Optional[Dict[str, Any]] = Field(None, description="Additional target information")
    confidence: float = Field(0.0, description="Confidence score (0.0 to 1.0)")
    attack_phase: str = Field(..., description="Current attack phase: osint, reconnaissance, enumeration, vulnerability_analysis, exploitation, post_exploitation, privilege_escalation, lateral_movement, credential_reuse")
    execution_channel: str = Field("local", description="local or managed_shell")
    handler_id: Optional[str] = Field(None, description="Managed shell handler id when execution_channel is managed_shell")
    msf_id: Optional[int] = Field(None, description="Managed Meterpreter/command-shell id when execution_channel is managed_shell")
    target_host: str = Field("", description="Concrete in-scope target host")
    target_port: int = Field(0, description="Concrete target port when applicable")
    action_type: str = Field("other", description="recon/exploit/post_exploit/pivot/validate")
    expected_result: str = Field("", description="Expected evidence for success")
    verification_method: str = Field("none", description="Tool-specific verification method")
    fallback_action: str = Field("", description="Next action if this action fails")


class KMN_AI_Connector:
    """AI connector supporting Ollama and multiple cloud API providers."""
    
    def __init__(self, provider: str = None, api_key: Optional[str] = None,
                 local_model: Optional[str] = None, ollama_url: Optional[str] = None,
                 api_model: Optional[str] = None):
        """
        Initialize AI connector.

        Args:
            provider: "local" for Ollama, "api" for DeepSeek API. If None, auto-detects based on API key.
            api_key: API key for DeepSeek API (optional, will check env vars if not provided)
            local_model: Ollama model tag to use, e.g. "qwen2.5:14b" or a security-tuned
                model like "DeepHat/DeepHat-V1-7B". Falls back to OLLAMA_MODEL env var,
                then a built-in default. Any model you've `ollama pull`ed works here.
            ollama_url: Base URL of the Ollama server, e.g. "http://localhost:11434".
                Falls back to OLLAMA_URL env var, then localhost default.
            api_model: DeepSeek API model name, e.g. "deepseek-chat" or "deepseek-coder".
                Falls back to DEEPSEEK_MODEL env var, then a built-in default.
        """
        # Load environment variables fresh
        load_dotenv(override=True)
        
        # Check for API key from parameter or environment variables
        requested_provider = (provider or os.getenv("AI_PROVIDER", "") or "").strip().lower()
        requested_provider = PROVIDER_ALIASES.get(requested_provider, requested_provider)
        if requested_provider not in API_PROVIDERS and requested_provider not in {"local", "none"}:
            requested_provider = ""

        key_env = {
            "deepseek": "DEEPSEEK_API_KEY", "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY", "openrouter": "OPENROUTER_API_KEY",
        }
        if not requested_provider:
            for candidate, env_name in key_env.items():
                if os.getenv(env_name):
                    requested_provider = candidate
                    break
            requested_provider = requested_provider or "local"
        # Check the provider-specific key; explicit api_key wins.
        self.api_key = api_key or os.getenv(key_env.get(requested_provider, ""), "")
        
        # Clean and validate API key
        if self.api_key:
            self.api_key = self.api_key.strip()
            
        # Define common placeholder patterns
        placeholder_patterns = [
            "your_deepseek_api_key_here",
            "your-api-key-here",
            "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "sk-test",
            "sk-demo",
            "placeholder",
            "example",
            "changeme",
            "insert_key_here"
        ]
        
        # Respect an explicit provider choice. A stale API key in .env must not
        # silently switch a user who selected local Ollama to remote inference.
        is_valid_api_key = (
            self.api_key and 
            len(self.api_key) > 10 and  # Reasonable minimum length for real API key
            not any(pattern in self.api_key.lower() for pattern in placeholder_patterns)
        )

        if requested_provider in API_PROVIDERS and not is_valid_api_key:
            logger.warning(
                f"AI_PROVIDER is '{requested_provider}' but no valid API key was found; falling back to local."
            )
            requested_provider = "local"
        self.provider = requested_provider
        if not is_valid_api_key:
            self.api_key = None
        logger.info(f"Using AI provider: {self.provider}")
        
        # URLs for different providers - explicit args win, then env vars, then defaults.
        ollama_base = (ollama_url or os.getenv("OLLAMA_URL") or "http://localhost:11434").strip().rstrip("/")
        if ollama_base.endswith("/api/generate"):
            ollama_base = ollama_base[: -len("/api/generate")].rstrip("/")
        self.ollama_url = f"{ollama_base}/api/generate"
        self.api_urls = {
            "deepseek": os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/chat/completions"),
            "openai": os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1/chat/completions"),
            "openrouter": os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1/chat/completions"),
            "anthropic": os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com/v1/messages"),
        }
        self.deepseek_api_url = self.api_urls["deepseek"]

        # Default models - configurable so any Ollama model (e.g. a security-tuned model
        # like DeepHat/DeepHat-V1-7B) can be used without code changes.
        self.local_model = local_model or os.getenv("OLLAMA_MODEL") or "qwen2.5:14b"
        model_env = {
            "deepseek": "DEEPSEEK_MODEL", "openai": "OPENAI_MODEL",
            "anthropic": "ANTHROPIC_MODEL", "openrouter": "OPENROUTER_MODEL",
        }
        defaults = {
            "deepseek": "deepseek-chat", "openai": "gpt-4o-mini",
            "anthropic": "claude-3-5-sonnet-latest", "openrouter": "openai/gpt-4o-mini",
        }
        self.api_model = api_model or os.getenv(model_env.get(requested_provider, ""), "") or defaults.get(requested_provider, "")
        
        # ── Context-window budget ─────────────────────────────────────────────
        # Read from env; user should set this to their Ollama model's num_ctx.
        # Common values: 4096 (small models), 8192 (mid), 32768 (large).
        # For the DeepSeek API provider this is effectively unlimited — we use
        # a very large placeholder so all budget checks pass.
        raw_ctx = os.getenv("OLLAMA_CONTEXT_WINDOW", "8192").strip()
        try:
            self.context_window: int = int(raw_ctx)
        except ValueError:
            self.context_window = 8192

        # ── Response budget ───────────────────────────────────────────────────
        # The full red-team system prompt asks for a reasoned analysis plus the
        # command, so the JSON reply can be long. A tight cap (the old hard-coded
        # 2000) truncates the reply mid-JSON; the parser then returns None and
        # the loop mistakes it for an "empty command" and stalls. Default higher
        # and make it configurable.
        try:
            self.max_tokens: int = int(os.getenv("AI_MAX_TOKENS", "4096").strip())
        except ValueError:
            self.max_tokens = 4096

        # ── Sampling temperature ──────────────────────────────────────────────
        # Tactical command selection wants determinism (fewer hallucinated flags
        # / CVEs / hostnames), so it defaults low. The strategist/critique passes
        # use their own lower temperature already.
        try:
            self.tactical_temperature: float = float(
                os.getenv("TACTICAL_TEMPERATURE", "0.2").strip()
            )
        except ValueError:
            self.tactical_temperature = 0.2

        logger.info(
            f"Initialized AI connector — provider={self.provider}, "
            f"context_window={self.context_window} tokens, "
            f"max_tokens={self.max_tokens}, tactical_temp={self.tactical_temperature}"
        )

    # ── Token budget helpers ──────────────────────────────────────────────────

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        """Rough token estimate: 1 token ≈ 4 characters (English + code mix).
        Good enough for budget planning; not a substitute for a tokenizer."""
        return max(1, len(text) // 4)

    def _budget_for_output(self) -> int:
        """Return max characters to include from a single command's output.
        Scales with the configured context window so small models get
        aggressively trimmed output while large models see the full result.

        Context tiers:
          < 4 K tokens  → 800 chars  (~200 tokens)
          4–8 K tokens  → 2 000 chars (~500 tokens)
          8–16 K tokens → 5 000 chars (~1 250 tokens)
          > 16 K tokens → 12 000 chars (~3 000 tokens)
        """
        cw = self.context_window
        if cw < 4_000:
            return 800
        if cw < 8_000:
            return 2_000
        if cw < 16_000:
            return 5_000
        return 12_000

    def _select_system_prompt(self, custom: Optional[str] = None) -> str:
        """Return the appropriate system prompt based on context window size.

        Tiers:
          < 8 K tokens → SYSTEM_PROMPT_COMPACT  (~700 tokens)
          ≥ 8 K tokens → SYSTEM_PROMPT (full, ~4 000 tokens)

        The compact prompt relies on the model's own pentest training for
        methodology details and only enforces the critical structural rules.
        """
        if custom:
            return custom
        from .prompts import SYSTEM_PROMPT, SYSTEM_PROMPT_COMPACT
        if self.provider in API_PROVIDERS:
            # API provider has a large context — always use full prompt
            return SYSTEM_PROMPT
        return SYSTEM_PROMPT_COMPACT if self.context_window < 8_000 else SYSTEM_PROMPT

    def _prepare_prompt(self, prompt: str, system_prompt: Optional[str] = None, memory: Optional[str] = None) -> str:
        """Prepare the complete prompt, respecting the configured context window.

        Budget allocation (approximate):
          system prompt  → _select_system_prompt() already picks compact vs full
          memory block   → trimmed to memory_budget chars
          prompt body    → passed as-is (orchestrator already trims cmd output)
          response       → reserve 20% of context_window for the JSON reply
        """
        system = self._select_system_prompt(system_prompt)

        # ── Memory budget ─────────────────────────────────────────────────────
        # For small-context models trim the memory JSON aggressively.
        cw = self.context_window
        if cw < 4_000:
            memory_budget_chars = 600
        elif cw < 8_000:
            memory_budget_chars = 1_600
        elif cw < 16_000:
            memory_budget_chars = 4_000
        else:
            memory_budget_chars = 10_000

        mem_block = ""
        if memory:
            trimmed_memory = memory[:memory_budget_chars]
            if len(memory) > memory_budget_chars:
                trimmed_memory += "\n... [memory trimmed for context budget]"
            mem_block = f"\n\n=== SESSION MEMORY ===\n{trimmed_memory}"

        full_prompt = (
            f"{system}"
            f"{mem_block}"
            f"\n\nCurrent Context:\n{prompt}"
            f"\n\nRespond with valid raw JSON only — no markdown, no extra text."
        )

        # ── Warn if we're over budget ─────────────────────────────────────────
        estimated = self._estimate_tokens(full_prompt)
        # Reserve 20% of context window for the model's response
        usable = int(cw * 0.80)
        if estimated > usable:
            logger.warning(
                f"Prompt estimated at {estimated} tokens but usable budget is "
                f"{usable} tokens (context_window={cw}). "
                "Consider increasing OLLAMA_CONTEXT_WINDOW or using a larger model."
            )

        return full_prompt
    
    def ask_ai_local(self, prompt: str, session_id: Optional[str] = None,
                     memory: Optional[str] = None) -> AIResponse:
        """Query local Ollama instance."""
        try:
            full_prompt = self._prepare_prompt(prompt, memory=memory)
            
            payload = {
                "model": self.local_model,
                "prompt": full_prompt,
                "stream": False,
                "options": {
                    "temperature": self.tactical_temperature,
                    "top_p": 0.9,
                    "top_k": 40,
                    # Tell Ollama to load the model with our configured context size.
                    # Without this, Ollama uses the model's baked-in default (often
                    # 2048 or 4096) even if the model supports more.
                    "num_ctx": self.context_window,
                    # Cap the reply length so a small model cannot ramble past the
                    # context budget, while still leaving room for a full JSON reply.
                    "num_predict": self.max_tokens,
                }
            }

            response = requests.post(self.ollama_url, json=payload, timeout=180)
            response.raise_for_status()
            
            result = response.json()
            response_text = result.get('response', '')

            # Parse JSON response — use robust extractor that handles markdown
            # fences, preamble text, and thinking tokens before the JSON blob.
            ai_data = _extract_json(response_text)
            if ai_data is None:
                logger.error(
                    f"Could not extract valid JSON from Ollama response "
                    f"(model={self.local_model}): {response_text[:500]}"
                )
                return None  # Caller (orchestrator) handles None: logs + stops session cleanly
            try:
                return AIResponse(**ai_data)
            except Exception as e:
                logger.error(f"AIResponse validation failed: {e} | data={ai_data}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Local AI request failed: {e}")
            raise ConnectionError(f"Failed to connect to local Ollama: {e}")
    
    async def ask_ai_api(self, prompt: str, session_id: Optional[str] = None, memory: Optional[str] = None) -> AIResponse:
        """Query a configured cloud provider using its native API shape."""
        if not self.api_key:
            raise ValueError(f"API key is required for {self.provider}")

        try:
            from .prompts import SYSTEM_PROMPT

            # ── Memory block (trimmed to API budget) ─────────────────────────
            mem_block = ""
            if memory:
                mem_budget = 10_000  # API has large context
                trimmed = memory[:mem_budget]
                if len(memory) > mem_budget:
                    trimmed += "\n... [memory trimmed for context budget]"
                mem_block = f"\n\n=== SESSION MEMORY ===\n{trimmed}"

            user_content = (
                f"{mem_block}"
                f"\n\nCurrent Context:\n{prompt}"
                f"\n\nRespond with valid raw JSON only — no markdown, no extra text."
            )

            if self.provider == "anthropic":
                headers = {
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                }
                base_payload = {
                    "model": self.api_model,
                    "system": SYSTEM_PROMPT,
                    "messages": [{"role": "user", "content": user_content}],
                    "max_tokens": self.max_tokens,
                }
            else:
                headers = {
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                }
                if self.provider == "openrouter":
                    headers.update({
                        "HTTP-Referer": os.getenv("OPENROUTER_HTTP_REFERER", "http://localhost"),
                        "X-Title": os.getenv("OPENROUTER_APP_NAME", "KMN-CyberSeek"),
                    })
                base_messages = [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_content}
                ]

            # Up to two attempts: the first at the configured tactical temperature,
            # and — if the reply is truncated or unparseable — a deterministic
            # repair pass at temperature 0 with a stricter, more compact-JSON
            # instruction. This turns a transient bad reply (the #1 cause of the
            # loop stalling on a phantom "empty command") into a self-heal.
            async with httpx.AsyncClient(timeout=90.0) as client:
                for attempt in range(2):
                    temperature = self.tactical_temperature
                    repair = ""
                    if attempt == 1:
                        temperature = 0.0
                        repair = (
                            "Your previous reply was invalid. Reply with ONLY one compact "
                            "JSON object matching the required schema. No markdown."
                        )
                    if self.provider == "anthropic":
                        payload = dict(base_payload)
                        payload["temperature"] = temperature
                        if repair:
                            payload["messages"] = [{"role": "user", "content": user_content + "\n\n" + repair}]
                    else:
                        messages = list(base_messages)
                        if repair:
                            messages.append({"role": "user", "content": repair})
                        payload = {
                            "model": self.api_model, "messages": messages,
                            "temperature": temperature, "max_tokens": self.max_tokens,
                        }
                        if self.provider in {"deepseek", "openai"}:
                            payload["response_format"] = {"type": "json_object"}

                    response = await client.post(
                        self.api_urls[self.provider], json=payload, headers=headers
                    )
                    response.raise_for_status()

                    result = response.json()
                    if self.provider == "anthropic":
                        response_text = "".join(
                            block.get("text", "") for block in result.get("content", [])
                            if block.get("type") == "text"
                        )
                        finish_reason = result.get("stop_reason")
                    else:
                        choice = result['choices'][0]
                        response_text = choice['message']['content']
                        finish_reason = choice.get('finish_reason')

                    # Parse JSON response — robust extractor handles fences/preamble.
                    ai_data = _extract_json(response_text)
                    truncated = finish_reason in ("length", "max_tokens")

                    if ai_data is not None and not truncated:
                        try:
                            return AIResponse(**ai_data)
                        except Exception as e:
                            logger.warning(
                                f"AIResponse validation failed (attempt {attempt + 1}): "
                                f"{e} | data={ai_data}"
                            )
                    else:
                        logger.warning(
                            f"API reply unusable (attempt {attempt + 1}, "
                            f"finish_reason={finish_reason}, model={self.api_model}): "
                            f"{response_text[:300]}"
                        )
                    # Fall through to the repair attempt.

                logger.error(
                    f"Could not obtain valid JSON from API after 2 attempts "
                    f"(model={self.api_model})."
                )
                return None  # Caller handles None: retry+visible-halt recovery

        except httpx.RequestError as e:
            logger.error(f"API request failed: {e}")
            raise ConnectionError(f"Failed to connect to DeepSeek API: {e}")
    
    def ask_ai(self, prompt: str, session_id: Optional[str] = None) -> AIResponse:
        """
        Synchronous wrapper for AI queries. NOTE: this cannot be called from
        inside a running event loop (e.g. FastAPI async handlers) - use
        'await ask_ai_async(...)' there instead. This wrapper is kept for
        standalone/CLI/test usage only.
        """
        if self.provider == "none":
            return None
        if self.provider in API_PROVIDERS:
            import asyncio
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                # No loop running in this thread - safe to drive one to completion.
                return asyncio.run(self.ask_ai_api(prompt, session_id))
            else:
                raise RuntimeError(
                    "KMN_AI_Connector.ask_ai() is synchronous and cannot be called from "
                    "inside a running event loop. Use 'await ask_ai_async(...)' instead."
                )
        else:
            # Local provider
            return self.ask_ai_local(prompt, session_id)
    
    async def ask_ai_async(self, prompt: str, session_id: Optional[str] = None, memory: Optional[str] = None) -> AIResponse:
        """
        Asynchronous AI query.
        """
        if self.provider == "none":
            return None
        if self.provider in API_PROVIDERS:
            return await self.ask_ai_api(prompt, session_id, memory)
        else:
            # Run local query in thread pool to avoid blocking
            import asyncio
            from concurrent.futures import ThreadPoolExecutor
            
            loop = asyncio.get_running_loop()
            with ThreadPoolExecutor() as executor:
                return await loop.run_in_executor(
                    executor,
                    lambda: self.ask_ai_local(prompt, session_id, memory)
                )
    
    async def ask_raw_async(self, system_prompt: str, user_prompt: str) -> Optional[Any]:
        """
        Query the AI with a fully custom system+user prompt and return raw parsed
        JSON - no AIResponse schema enforced (no reasoning/suggested_command/etc
        required). For non-pentest-reasoning tasks like structured data extraction
        (e.g. core/threat_intel.py), kept deliberately separate from
        ai/prompts.py SYSTEM_PROMPT so extraction tasks can never smuggle a
        suggested_command into the live exploitation loop.

        Returns None on any failure (invalid JSON, network error, etc) - never raises.
        """
        try:
            if self.provider == "none":
                return None
            if self.provider in API_PROVIDERS:
                return await self._ask_raw_api(system_prompt, user_prompt)
            else:
                import asyncio
                from concurrent.futures import ThreadPoolExecutor

                loop = asyncio.get_running_loop()
                with ThreadPoolExecutor() as executor:
                    return await loop.run_in_executor(
                        executor, lambda: self._ask_raw_local(system_prompt, user_prompt)
                    )
        except Exception as e:
            logger.warning(f"ask_raw_async failed (non-fatal): {e}")
            return None

    async def _ask_raw_api(self, system_prompt: str, user_prompt: str) -> Optional[Any]:
        if not self.api_key:
            return None

        if self.provider == "anthropic":
            headers = {
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            }
            payload = {
                "model": self.api_model, "system": system_prompt,
                "messages": [{"role": "user", "content": user_prompt}],
                "temperature": 0.3, "max_tokens": self.max_tokens,
            }
        else:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            if self.provider == "openrouter":
                headers.update({
                    "HTTP-Referer": os.getenv("OPENROUTER_HTTP_REFERER", "http://localhost"),
                    "X-Title": os.getenv("OPENROUTER_APP_NAME", "KMN-CyberSeek"),
                })
            payload = {
                "model": self.api_model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": 0.3,
                "max_tokens": self.max_tokens,
            }

        async with httpx.AsyncClient(timeout=90.0) as client:
            response = await client.post(
                self.api_urls[self.provider], json=payload, headers=headers
            )
            response.raise_for_status()
            result = response.json()
            if self.provider == "anthropic":
                text = "".join(
                    block.get("text", "") for block in result.get("content", [])
                    if block.get("type") == "text"
                )
            else:
                text = result['choices'][0]['message']['content']
            return self._extract_json(text)

    def _ask_raw_local(self, system_prompt: str, user_prompt: str) -> Optional[Any]:
        full_prompt = f"{system_prompt}\n\n{user_prompt}"
        payload = {
            "model": self.local_model,
            "prompt": full_prompt,
            "stream": False,
            "options": {"temperature": 0.3, "num_ctx": self.context_window},
        }
        response = requests.post(self.ollama_url, json=payload, timeout=60)
        response.raise_for_status()
        result = response.json()
        text = result.get('response', '')
        return self._extract_json(text)

    @staticmethod
    def _extract_json(text: str) -> Optional[Any]:
        """Best-effort JSON extraction from a raw model response: strips markdown
        code fences and grabs the first {...} or [...] block."""
        import re
        text = text.strip()
        text = re.sub(r'^```(?:json)?\s*|\s*```$', '', text, flags=re.MULTILINE).strip()
        match = re.search(r'(\[.*\]|\{.*\})', text, re.DOTALL)
        if match:
            text = match.group(1)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            logger.warning(f"ask_raw_async: failed to parse JSON from model response: {text[:200]}")
            return None


# Helper function for backward compatibility
def get_ai_connector(provider: str = "local", api_key: Optional[str] = None) -> KMN_AI_Connector:
    """Factory function to get AI connector instance."""
    return KMN_AI_Connector(provider=provider, api_key=api_key)
