"""
Prototype Pollution Detection Tool

A tool for detecting client-side prototype pollution vulnerabilities in JavaScript code.
"""

__version__ = "0.2.0"
__author__ = "Letao Zhao, Ethan Lee, Bingyan He, Qi Sun"

from .detector import PrototypePollutionDetector
from .github_crawler import GitHubCrawler, CodeSnippet
from .crawler_orchestrator import CrawlerOrchestrator
from .llm_analyzer import LLMAnalyzer, LLMAnalysisResult
from .config import Config, config

__all__ = [
    "PrototypePollutionDetector",
    "GitHubCrawler",
    "CodeSnippet",
    "CrawlerOrchestrator",
    "LLMAnalyzer",
    "LLMAnalysisResult",
    "Config",
    "config",
]
