"""
Configuration module for managing environment variables and settings.
"""

import os
from pathlib import Path
from typing import Optional

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None


class Config:
    """Configuration manager for API keys and settings."""
    
    def __init__(self):
        """Initialize configuration and load environment variables."""
        # Load .env file if dotenv is available
        if load_dotenv:
            env_path = Path(__file__).parent.parent.parent / ".env"
            load_dotenv(env_path)
        
        self.openai_api_key: Optional[str] = os.getenv("OPENAI_API_KEY")
        self.github_token: Optional[str] = os.getenv("GITHUB_TOKEN")
        
        # Rate limiting settings
        self.github_rate_limit: int = int(os.getenv("GITHUB_RATE_LIMIT", "30"))
        self.openai_rate_limit: int = int(os.getenv("OPENAI_RATE_LIMIT", "60"))
    
    def validate(self) -> dict:
        """
        Validate that required API keys are present.
        
        Returns:
            Dictionary with validation results
        """
        missing = []
        warnings = []
        
        if not self.openai_api_key:
            warnings.append("OPENAI_API_KEY not set - LLM features will be disabled")
        
        if not self.github_token:
            warnings.append("GITHUB_TOKEN not set - GitHub code search requires authentication")
        
        return {
            "valid": len(missing) == 0,
            "missing": missing,
            "warnings": warnings,
        }
    
    def get_openai_key(self) -> Optional[str]:
        """Get OpenAI API key."""
        return self.openai_api_key
    
    def get_github_token(self) -> Optional[str]:
        """Get GitHub token."""
        return self.github_token


# Global config instance
config = Config()

