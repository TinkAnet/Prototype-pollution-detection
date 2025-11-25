"""
PolluTaint - Taint Analysis Tool for Prototype Pollution Detection

A static analysis tool for detecting prototype pollution vulnerabilities in JavaScript code
using semantic AST analysis and taint tracking.
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
