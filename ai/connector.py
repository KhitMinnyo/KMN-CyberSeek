"""
KMN-CyberSeek AI Connector Module
Supports both local Ollama (DeepSeek models) and DeepSeek API
"""

import json
import logging
import os
from typing import Dict, List, Optional, Any

from dotenv import load_dotenv
# Force reload environment variables to ensure fresh values
load_dotenv(override=True)

import httpx
import requests
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class AIResponse(BaseModel):
    """Standardized AI response format."""
    reasoning: str = Field(..., description="AI's thought process and analysis")
    suggested_command: str = Field(..., description="Command to execute")
    risk_level: str = Field(..., description="low/medium/high risk classification")
    target_info: Optional[Dict[str, Any]] = Field(None, description="Additional target information")
    confidence: float = Field(0.0, description="Confidence score (0.0 to 1.0)")
    attack_phase: str = Field(..., description="Current attack phase: osint, reconnaissance, enumeration, vulnerability_analysis, exploitation, post_exploitation, privilege_escalation, lateral_movement, credential_reuse")


class KMN_AI_Connector:
    """Hybrid AI connector supporting local Ollama and DeepSeek API."""
    
    def __init__(self, provider: str = None, api_key: Optional[str] = None,
                 local_model: Optional[str] = None, ollama_url: Optional[str] = None,
                 api_model: Optional[str] = None):
        """
        Initialize AI connector.

        Args:
            provider: "local" for Ollama, "api" for DeepSeek API. If None, auto-detects based on API key.
            api_key: API key for DeepSeek API (optional, will check env vars if not provided)
            local_model: Ollama model tag to use, e.g. "deepseek-r1:8b" or a security-tuned
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
        # Check both DEEPSEEK_API_KEY and OPENAI_API_KEY as mentioned in feedback
        self.api_key = api_key or os.getenv("DEEPSEEK_API_KEY") or os.getenv("OPENAI_API_KEY")
        
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
        
        # FORCE API mode if we have a valid, non-placeholder API key
        is_valid_api_key = (
            self.api_key and 
            len(self.api_key) > 10 and  # Reasonable minimum length for real API key
            not any(pattern in self.api_key.lower() for pattern in placeholder_patterns)
        )
        
        if is_valid_api_key:
            self.provider = "api"
            logger.info("Valid API key found. Forcing AI provider to: API")
        else:
            # Only use local if explicitly requested AND no valid API key exists
            self.provider = provider or os.getenv("AI_PROVIDER", "local")
            if self.provider == "api" and not is_valid_api_key:
                logger.warning("AI_PROVIDER set to 'api' but no valid API key found. Falling back to local.")
                self.provider = "local"
            logger.info(f"No valid API key found. Using provider: {self.provider}")
            # Clear API key if it's invalid/placeholder
            self.api_key = None
        
        # URLs for different providers - explicit args win, then env vars, then defaults.
        ollama_base = (ollama_url or os.getenv("OLLAMA_URL") or "http://localhost:11434").strip().rstrip("/")
        if ollama_base.endswith("/api/generate"):
            ollama_base = ollama_base[: -len("/api/generate")].rstrip("/")
        self.ollama_url = f"{ollama_base}/api/generate"
        self.deepseek_api_url = "https://api.deepseek.com/chat/completions"

        # Default models - configurable so any Ollama model (e.g. a security-tuned model
        # like DeepHat/DeepHat-V1-7B) can be used without code changes.
        self.local_model = local_model or os.getenv("OLLAMA_MODEL") or "deepseek-r1:8b"
        self.api_model = api_model or os.getenv("DEEPSEEK_MODEL") or "deepseek-chat"
        
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

        logger.info(
            f"Initialized AI connector — provider={self.provider}, "
            f"context_window={self.context_window} tokens"
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
        if self.provider == "api":
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
                    "temperature": 0.7,
                    "top_p": 0.9,
                    "top_k": 40,
                    # Tell Ollama to load the model with our configured context size.
                    # Without this, Ollama uses the model's baked-in default (often
                    # 2048 or 4096) even if the model supports more.
                    "num_ctx": self.context_window,
                }
            }

            response = requests.post(self.ollama_url, json=payload, timeout=120)
            response.raise_for_status()
            
            result = response.json()
            response_text = result.get('response', '{}')
            
            # Parse JSON response
            try:
                # Extract JSON from response (handles cases where AI adds extra text)
                import re
                json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
                if json_match:
                    response_text = json_match.group(0)
                
                ai_data = json.loads(response_text)
                return AIResponse(**ai_data)
                
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse AI response: {response_text}")
                # Fallback response
                return AIResponse(
                    reasoning="Failed to parse AI response",
                    suggested_command="echo 'AI response parsing error'",
                    risk_level="low",
                    confidence=0.0,
                    attack_phase="reconnaissance"
                )
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Local AI request failed: {e}")
            raise ConnectionError(f"Failed to connect to local Ollama: {e}")
    
    async def ask_ai_api(self, prompt: str, session_id: Optional[str] = None, memory: Optional[str] = None) -> AIResponse:
        """Query DeepSeek API.

        System prompt goes in the `system` role (not buried in the user message)
        so the model gives it maximum weight. Memory + context go in `user`.
        """
        if not self.api_key:
            raise ValueError("DeepSeek API key is required for API provider")

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

            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }

            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_content}
            ]

            payload = {
                "model": self.api_model,
                "messages": messages,
                "temperature": 0.7,
                "max_tokens": 2000,
                "response_format": {"type": "json_object"}
            }
            
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(self.deepseek_api_url, json=payload, headers=headers)
                response.raise_for_status()
                
                result = response.json()
                response_text = result['choices'][0]['message']['content']
                
                # Parse JSON response
                try:
                    ai_data = json.loads(response_text)
                    return AIResponse(**ai_data)
                    
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse API response: {response_text}")
                    # Fallback response
                    return AIResponse(
                        reasoning="Failed to parse AI response",
                        suggested_command="echo 'AI response parsing error'",
                        risk_level="low",
                        confidence=0.0,
                        attack_phase="reconnaissance"
                    )
                    
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
        if self.provider == "api":
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
        if self.provider == "api":
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
            if self.provider == "api":
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

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        payload = {
            "model": self.api_model,
            "messages": messages,
            "temperature": 0.3,
            "max_tokens": 2000,
        }

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(self.deepseek_api_url, json=payload, headers=headers)
            response.raise_for_status()
            result = response.json()
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