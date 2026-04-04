"""
KMN-CyberSeek AI Connector Module
Supports both local Ollama (DeepSeek models) and DeepSeek API
"""

import json
import logging
import os
from datetime import datetime
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
    attack_phase: str = Field(..., description="Current attack phase: reconnaissance, vulnerability_analysis, exploitation, post_exploitation, lateral_movement")


class KMN_AI_Connector:
    """Hybrid AI connector supporting local Ollama and DeepSeek API."""
    
    def __init__(self, provider: str = None, api_key: Optional[str] = None):
        """
        Initialize AI connector.
        
        Args:
            provider: "local" for Ollama, "api" for DeepSeek API. If None, auto-detects based on API key.
            api_key: API key for DeepSeek API (optional, will check env vars if not provided)
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
            logger.info(f"Valid API Key found: {self.api_key[:10]}... Forcing AI provider to: API")
        else:
            # Only use local if explicitly requested AND no valid API key exists
            self.provider = provider or os.getenv("AI_PROVIDER", "local")
            if self.provider == "api" and not is_valid_api_key:
                logger.warning("AI_PROVIDER set to 'api' but no valid API key found. Falling back to local.")
                self.provider = "local"
            logger.info(f"No valid API key found. Using provider: {self.provider}")
            # Clear API key if it's invalid/placeholder
            self.api_key = None
        
        # URLs for different providers
        self.ollama_url = "http://localhost:11434/api/generate"
        self.deepseek_api_url = "https://api.deepseek.com/chat/completions"
        
        # Default models
        self.local_model = "deepseek-r1:8b"  # or "deepseek-v2:latest"
        self.api_model = "deepseek-chat"
        
        # Session history for context
        self.session_history: Dict[str, List[Dict]] = {}
        
        logger.info(f"Initialized AI connector with provider: {self.provider}")
    
    def _prepare_prompt(self, prompt: str, system_prompt: Optional[str] = None, memory: Optional[str] = None) -> str:
        """Prepare the complete prompt with system instructions."""
        from .prompts import SYSTEM_PROMPT
        
        system = system_prompt or SYSTEM_PROMPT
        
        # Format system prompt with memory if provided
        if memory is not None:
            try:
                system = system.format(memory=memory)
            except KeyError as e:
                logger.warning(f"Failed to format SYSTEM_PROMPT with memory: {e}. Memory placeholder may be missing.")
            except Exception as e:
                logger.warning(f"Error formatting SYSTEM_PROMPT: {e}")
        
        full_prompt = f"""{system}

Current Context:
{prompt}

Please analyze the above information and provide your response in the following JSON format:
{{
    "reasoning": "Your detailed thought process and analysis...",
    "suggested_command": "The exact CLI command to execute next",
    "risk_level": "low/medium/high",
    "attack_phase": "reconnaissance/vulnerability_analysis/exploitation/post_exploitation/lateral_movement",
    "confidence": 0.85,
    "target_info": {{"key": "value"}}  # Optional field
}}

Important: Your response must be valid JSON only, no additional text."""
        
        return full_prompt
    
    def ask_ai_local(self, prompt: str, session_id: Optional[str] = None) -> AIResponse:
        """Query local Ollama instance."""
        try:
            full_prompt = self._prepare_prompt(prompt)
            
            payload = {
                "model": self.local_model,
                "prompt": full_prompt,
                "stream": False,
                "options": {
                    "temperature": 0.7,
                    "top_p": 0.9,
                    "top_k": 40
                }
            }
            
            response = requests.post(self.ollama_url, json=payload, timeout=60)
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
        """Query DeepSeek API."""
        if not self.api_key:
            raise ValueError("DeepSeek API key is required for API provider")
        
        try:
            full_prompt = self._prepare_prompt(prompt, memory=memory)
            
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            messages = [
                {"role": "system", "content": "You are KMN-CyberSeek, an AI red team operator."},
                {"role": "user", "content": full_prompt}
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
        Synchronous wrapper for AI queries.
        """
        if self.provider == "api":
            # For async API calls, we need to run in event loop
            import asyncio
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            
            return loop.run_until_complete(self.ask_ai_api(prompt, session_id))
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
            
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                return await loop.run_in_executor(
                    executor, 
                    lambda: self.ask_ai_local(prompt, session_id)
                )
    
    def add_to_history(self, session_id: str, role: str, content: str):
        """Add message to session history for context."""
        if session_id not in self.session_history:
            self.session_history[session_id] = []
        
        self.session_history[session_id].append({
            "role": role,
            "content": content,
            "timestamp": str(datetime.now())
        })
        
        # Keep only last 20 messages to avoid context overflow
        if len(self.session_history[session_id]) > 20:
            self.session_history[session_id] = self.session_history[session_id][-20:]
    
    def get_session_history(self, session_id: str) -> List[Dict]:
        """Get conversation history for a session."""
        return self.session_history.get(session_id, [])
    
    def clear_session_history(self, session_id: str):
        """Clear conversation history for a session."""
        if session_id in self.session_history:
            del self.session_history[session_id]


# Helper function for backward compatibility
def get_ai_connector(provider: str = "local", api_key: Optional[str] = None) -> KMN_AI_Connector:
    """Factory function to get AI connector instance."""
    return KMN_AI_Connector(provider=provider, api_key=api_key)