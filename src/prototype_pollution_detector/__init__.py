"""
Prototype Pollution Detection Tool

A tool for detecting client-side prototype pollution vulnerabilities in JavaScript code.
"""

__version__ = "0.1.0"
__author__ = "Letao Zhao, Ethan Lee, Bingyan He, Qi Sun"

from .detector import PrototypePollutionDetector

__all__ = ["PrototypePollutionDetector"]
