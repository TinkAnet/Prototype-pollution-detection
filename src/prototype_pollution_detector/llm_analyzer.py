"""
LLM-assisted analyzer for prototype pollution detection.

This module uses OpenAI's API to help analyze code snippets and filter
potential vulnerabilities.
"""

import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from .config import config


@dataclass
class LLMAnalysisResult:
    """Result from LLM analysis."""
    is_vulnerable: bool
    confidence: float  # 0.0 to 1.0
    explanation: str
    vulnerability_type: Optional[str] = None
    severity: Optional[str] = None


class LLMAnalyzer:
    """
    LLM-powered analyzer for prototype pollution detection.
    
    Uses OpenAI API to analyze code snippets and provide additional
    context and filtering for potential vulnerabilities.
    """
    
    def __init__(self, verbose: bool = False):
        """
        Initialize the LLM analyzer.
        
        Args:
            verbose: Enable verbose output
        """
        self.verbose = verbose
        self.api_key = config.get_openai_key()
        self.client = None
        
        if self.api_key:
            try:
                from openai import OpenAI
                self.client = OpenAI(api_key=self.api_key)
            except ImportError:
                if verbose:
                    print("Warning: openai package not installed. LLM features disabled.")
            except Exception as e:
                if verbose:
                    print(f"Warning: Could not initialize OpenAI client: {e}")
        else:
            if verbose:
                print("Warning: OPENAI_API_KEY not set. LLM features disabled.")
    
    def is_available(self) -> bool:
        """Check if LLM analyzer is available."""
        return self.client is not None
    
    def analyze_code_snippet(
        self,
        code: str,
        context: Optional[str] = None,
        language: str = "javascript"
    ) -> Optional[LLMAnalysisResult]:
        """
        Analyze a code snippet for prototype pollution vulnerabilities.
        
        Args:
            code: Code snippet to analyze
            context: Additional context (file path, repository, etc.)
            language: Programming language (default: javascript)
            
        Returns:
            LLMAnalysisResult if analysis successful, None otherwise
        """
        if not self.is_available():
            return None
        
        try:
            prompt = self._build_analysis_prompt(code, context, language)
            response = self.client.chat.completions.create(
                model="gpt-4o-mini",  # Using cheaper model for cost efficiency
                messages=[
                    {
                        "role": "system",
                        "content": self._get_system_prompt(),
                    },
                    {
                        "role": "user",
                        "content": prompt,
                    },
                ],
                temperature=0.3,  # Lower temperature for more consistent results
                max_tokens=500,
            )
            
            result_text = response.choices[0].message.content
            return self._parse_response(result_text)
        
        except Exception as e:
            if self.verbose:
                print(f"Error in LLM analysis: {e}")
            return None
    
    def filter_vulnerable_snippets(
        self,
        snippets: List[Dict[str, Any]],
        max_analyze: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Filter code snippets using LLM to identify most likely vulnerabilities.
        
        Args:
            snippets: List of code snippet dictionaries
            max_analyze: Maximum number of snippets to analyze
            
        Returns:
            Filtered list of snippets ranked by vulnerability likelihood
        """
        if not self.is_available():
            return snippets[:max_analyze]  # Return first N if LLM unavailable
        
        analyzed = []
        for snippet in snippets[:max_analyze]:
            code = snippet.get("code", "")
            context = snippet.get("file_path", "")
            
            result = self.analyze_code_snippet(code, context)
            if result and result.is_vulnerable:
                snippet["llm_analysis"] = {
                    "is_vulnerable": result.is_vulnerable,
                    "confidence": result.confidence,
                    "explanation": result.explanation,
                    "vulnerability_type": result.vulnerability_type,
                    "severity": result.severity,
                }
                analyzed.append(snippet)
        
        # Sort by confidence (highest first)
        analyzed.sort(
            key=lambda x: x.get("llm_analysis", {}).get("confidence", 0.0),
            reverse=True
        )
        
        return analyzed
    
    def _build_analysis_prompt(
        self,
        code: str,
        context: Optional[str],
        language: str
    ) -> str:
        """Build the analysis prompt for the LLM."""
        prompt = f"""Analyze the following {language} code snippet for prototype pollution vulnerabilities.

Code:
```{language}
{code}
```

"""
        if context:
            prompt += f"Context: {context}\n\n"
        
        prompt += """Please analyze this code and determine:
1. Is this code vulnerable to prototype pollution?
2. What is your confidence level (0.0 to 1.0)?
3. What type of vulnerability is it (if any)?
4. What is the severity (high/medium/low)?
5. Provide a brief explanation.

Respond in JSON format:
{
    "is_vulnerable": true/false,
    "confidence": 0.0-1.0,
    "vulnerability_type": "type or null",
    "severity": "high/medium/low or null",
    "explanation": "brief explanation"
}
"""
        return prompt
    
    def _get_system_prompt(self) -> str:
        """Get the system prompt for the LLM."""
        return """You are a security expert specializing in JavaScript prototype pollution vulnerabilities.

Prototype pollution occurs when:
1. Code merges/extends objects without validating property names
2. Dangerous properties like __proto__, constructor, or prototype are assigned
3. User-controlled data (e.g., from JSON.parse) is merged into objects
4. HTML injection vectors parse JSON from DOM attributes and merge without validation

Common patterns to look for:
- Unsafe extend/merge functions without property validation
- JSON.parse() on DOM attributes followed by object merging
- Direct assignments to __proto__, constructor, or prototype
- Recursive object copying without safeguards

Be precise and conservative - only flag code that is clearly vulnerable or highly suspicious."""
    
    def _parse_response(self, response_text: str) -> Optional[LLMAnalysisResult]:
        """Parse LLM response into LLMAnalysisResult."""
        try:
            # Try to extract JSON from response
            json_start = response_text.find("{")
            json_end = response_text.rfind("}") + 1
            
            if json_start >= 0 and json_end > json_start:
                json_str = response_text[json_start:json_end]
                data = json.loads(json_str)
                
                return LLMAnalysisResult(
                    is_vulnerable=data.get("is_vulnerable", False),
                    confidence=float(data.get("confidence", 0.0)),
                    explanation=data.get("explanation", ""),
                    vulnerability_type=data.get("vulnerability_type"),
                    severity=data.get("severity"),
                )
        except (json.JSONDecodeError, ValueError, KeyError) as e:
            if self.verbose:
                print(f"Error parsing LLM response: {e}")
        
        return None
    
    def summarize_findings(self, findings: List[Dict[str, Any]]) -> Optional[str]:
        """
        Generate a summary of findings using LLM.
        
        Args:
            findings: List of vulnerability findings
            
        Returns:
            Summary text or None if LLM unavailable
        """
        if not self.is_available() or not findings:
            return None
        
        try:
            findings_summary = json.dumps(findings[:20], indent=2)  # Limit to first 20
            
            prompt = f"""Summarize the following prototype pollution vulnerability findings:

{findings_summary}

Provide a concise summary highlighting:
1. Total number of vulnerabilities found
2. Most common vulnerability types
3. Most critical findings
4. Recommendations

Keep it brief and actionable."""
            
            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a security expert providing vulnerability summaries.",
                    },
                    {
                        "role": "user",
                        "content": prompt,
                    },
                ],
                temperature=0.5,
                max_tokens=300,
            )
            
            return response.choices[0].message.content
        
        except Exception as e:
            if self.verbose:
                print(f"Error generating summary: {e}")
            return None

