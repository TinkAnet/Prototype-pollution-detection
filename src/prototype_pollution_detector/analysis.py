"""
Analysis module for detecting prototype pollution patterns.

This module contains the core logic for analyzing parsed JavaScript code
and HTML files to identify potential prototype pollution vulnerabilities.
"""

import json
import re
from typing import Dict, List, Any, Set, Optional
from dataclasses import dataclass


@dataclass
class Vulnerability:
    """
    Represents a detected prototype pollution vulnerability.
    """
    severity: str  # 'high', 'medium', 'low'
    line: int
    column: int
    message: str
    code_snippet: str
    vulnerability_type: str


class PrototypePollutionAnalyzer:
    """
    Analyzer for detecting prototype pollution vulnerabilities.
    
    This class implements various heuristics and patterns to identify
    potential prototype pollution issues in JavaScript code and HTML files.
    """
    
    # Common dangerous property names that could lead to pollution
    DANGEROUS_PROPERTIES = {
        "__proto__",
        "prototype",
        "constructor",
    }
    
    def __init__(self, verbose: bool = False):
        """
        Initialize the analyzer.
        
        Args:
            verbose: Enable verbose output
        """
        self.verbose = verbose
        self.vulnerabilities: List[Vulnerability] = []
    
    def analyze_ast(self, ast: Dict[str, Any]) -> List[Vulnerability]:
        """
        Analyze an AST for prototype pollution vulnerabilities.
        
        Focus: Detect vulnerable merge/extend functions (source functions).
        
        Args:
            ast: Parsed AST dictionary (from parser)
            
        Returns:
            List of detected vulnerabilities
        """
        self.vulnerabilities = []
        
        if self.verbose:
            print(f"Analyzing AST from {ast.get('file', 'unknown')}")
        
        file_type = ast.get("file_type", "javascript")
        
        # For HTML files, extract JavaScript and analyze merge functions
        if file_type == "html":
            # Extract JavaScript from HTML and analyze merge functions
            self._analyze_html_for_merge_functions(ast)
        else:
            # Analyze JavaScript for merge/extend functions
            self._analyze_javascript_code(ast)
        
        return self.vulnerabilities
    
    def _analyze_html_for_merge_functions(self, ast: Dict[str, Any]) -> None:
        """
        Analyze HTML file to extract JavaScript and detect vulnerable merge/extend functions.
        
        Focus: Only detect merge/extend functions, not HTML injection vectors.
        
        Args:
            ast: Parsed HTML AST dictionary
        """
        # Analyze inline JavaScript in HTML for merge functions
        for inline_script in ast.get("inline_scripts", []):
            self._analyze_javascript_code(inline_script)
        
        # Analyze script tags for merge functions
        for script_tag in ast.get("script_tags", []):
            script_content = script_tag.get("content", "")
            if script_content:
                # Parse the script content and analyze all functions
                try:
                    from .parser import JavaScriptParser
                    parser = JavaScriptParser(verbose=self.verbose)
                    script_ast = parser.parse_code(script_content, ast.get("file", ""))
                    self._analyze_javascript_code(script_ast)
                except Exception:
                    # If parsing fails, try to extract functions via regex
                    self._extract_functions_from_code(script_content, script_tag.get("line", 0))
    
    def _extract_functions_from_code(self, code: str, start_line: int = 0) -> None:
        """
        Extract function definitions from raw code using regex.
        
        Used as fallback when AST parsing fails.
        
        Args:
            code: JavaScript code string
            start_line: Starting line number
        """
        if start_line is None or not isinstance(start_line, int):
            start_line = 0
        
        # Pattern to find function declarations: function name(...) { ... }
        func_pattern = r'function\s+(\w+)\s*\([^)]*\)\s*\{([^}]*)\}'
        for match in re.finditer(func_pattern, code, re.IGNORECASE | re.DOTALL):
            func_name = match.group(1)
            func_body = match.group(2)
            line_num = start_line + code[:match.start()].count("\n")
            
            # Check if this function does property copying
            if self._has_property_copying_pattern(func_body):
                # Check if it validates
                has_validation = self._has_property_validation(func_body)
                
                if not has_validation:
                    self.vulnerabilities.append(Vulnerability(
                        severity="high",
                        line=line_num,
                        column=0,
                        message=(
                            f"Function '{func_name}' performs property copying/merging "
                            f"without validating dangerous properties. This makes it vulnerable "
                            f"to prototype pollution attacks."
                        ),
                        code_snippet=match.group(0)[:300],
                        vulnerability_type="vulnerable_property_copying",
                    ))
    
    def _has_property_copying_pattern(self, code: str) -> bool:
        """
        Check if code contains recursive merge patterns.
        
        Args:
            code: Code string to check
            
        Returns:
            True if recursive merge pattern is found
        """
        # Check for recursive merge indicators
        patterns = [
            r'for\s*\([^)]*\s+in\s+[^)]*\)',  # for...in loop
            r'typeof\s+[^=]+\s*===\s*["\']object["\']',  # Type checking
            r'\[[^\]]+\]\s*=\s*',  # Property assignment
        ]
        return any(re.search(pattern, code, re.IGNORECASE) for pattern in patterns)
    
    def _analyze_javascript_code(self, ast: Dict[str, Any]) -> None:
        """
        Analyze ALL functions in JavaScript code for prototype pollution vulnerabilities.
        
        Checks every function to see if its logic is vulnerable, not just functions
        with suspicious names.
        
        Args:
            ast: Parsed JavaScript AST dictionary
        """
        # Analyze ALL functions, not just those with merge/extend names
        functions = ast.get("functions", [])
        for func in functions:
            # Check if this function's logic is vulnerable to prototype pollution
            self._check_function_vulnerability(func, ast)
        
        # Check for direct dangerous property assignments
        assignments = ast.get("assignments", [])
        for assign in assignments:
            prop_name = assign.get("property", "")
            if prop_name in self.DANGEROUS_PROPERTIES:
                self.vulnerabilities.append(Vulnerability(
                    severity="high",
                    line=assign.get("line", 0) or 0,
                    column=assign.get("column", 0) or 0,
                    message=(
                        f"Direct assignment to dangerous property '{prop_name}'. "
                        f"This could lead to prototype pollution."
                    ),
                    code_snippet=assign.get("code", ""),
                    vulnerability_type="direct_dangerous_property_assignment",
                ))
    
    def _check_function_vulnerability(self, func: Dict[str, Any], ast: Dict[str, Any]) -> None:
        """
        Check if a function's logic is vulnerable to prototype pollution.
        
        Focus: Detects recursive/deep merge functions that are vulnerable.
        Prototype pollution typically occurs in recursive merge functions that
        traverse nested objects without validating dangerous properties.
        
        Args:
            func: Function information dictionary
            ast: Full AST dictionary
        """
        func_name = func.get("name", "") or ""
        func_body = func.get("body", "")
        func_line = func.get("line", 0) or 0
        func_column = func.get("column", 0) or 0
        
        if not func_body:
            return
        
        # Focus on recursive/deep merge patterns - these are the main source of prototype pollution
        is_recursive_merge = self._is_recursive_merge_function(func_name, func_body, ast)
        
        if is_recursive_merge:
            # Check if function validates dangerous properties
            has_validation = self._has_property_validation(func_body)
            
            if not has_validation:
                # This recursive merge function is vulnerable!
                func_display_name = func_name if func_name else "(anonymous)"
                self.vulnerabilities.append(Vulnerability(
                    severity="high",
                    line=func_line,
                    column=func_column,
                    message=(
                        f"Recursive merge function '{func_display_name}' performs deep property copying "
                        f"without validating dangerous properties (__proto__, constructor, prototype). "
                        f"This makes it vulnerable to prototype pollution attacks."
                    ),
                    code_snippet=func_body[:300] if len(func_body) > 300 else func_body,
                    vulnerability_type="vulnerable_recursive_merge",
                ))
            elif self._has_partial_validation(func_body):
                # Partial validation - still potentially unsafe
                func_display_name = func_name if func_name else "(anonymous)"
                self.vulnerabilities.append(Vulnerability(
                    severity="medium",
                    line=func_line,
                    column=func_column,
                    message=(
                        f"Recursive merge function '{func_display_name}' performs deep property copying "
                        f"with partial validation. Please verify that all dangerous properties "
                        f"are properly checked before recursive merging."
                    ),
                    code_snippet=func_body[:300] if len(func_body) > 300 else func_body,
                    vulnerability_type="partially_safe_recursive_merge",
                ))
    
    def _is_recursive_merge_function(self, func_name: str, func_body: str, ast: Dict[str, Any]) -> bool:
        """
        Check if a function is a recursive/deep merge function.
        
        Recursive merge functions are the main source of prototype pollution because
        they traverse nested objects and can copy properties from __proto__.
        
        Args:
            func_name: Function name
            func_body: Function body code
            ast: Full AST dictionary
            
        Returns:
            True if this is a recursive merge function
        """
        # Pattern 1: Function calls itself recursively (classic recursive merge)
        if func_name:
            # Check if function calls itself: extend(out[key], val) or merge(target[key], source[key])
            recursive_call_pattern = rf'\b{re.escape(func_name)}\s*\('
            if re.search(recursive_call_pattern, func_body, re.IGNORECASE):
                # Also check if it's merging nested objects
                if self._has_nested_object_merge_pattern(func_body):
                    return True
        
        # Pattern 2: Deep merge pattern - checks if value is object and merges recursively
        # e.g., if (typeof val === 'object') { merge(target[key], val); }
        deep_merge_patterns = [
            r'typeof\s+[^=]+\s*===\s*["\']object["\']',
            r'typeof\s+[^=]+\s*==\s*["\']object["\']',
            r'val\s*!=\s*null\s*&&\s*typeof\s+val\s*===\s*["\']object["\']',
            r'Array\.isArray\s*\(',
        ]
        
        has_type_check = any(
            re.search(pattern, func_body, re.IGNORECASE)
            for pattern in deep_merge_patterns
        )
        
        # Pattern 3: Checks for nested objects and then does recursive assignment
        # e.g., if (out[key] != null && typeof out[key] === 'object') { extend(out[key], val); }
        has_nested_merge = self._has_nested_object_merge_pattern(func_body)
        
        # Pattern 4: Uses Object.assign or spread with nested object handling
        has_object_assign_with_nesting = (
            'Object.assign' in func_body and
            ('typeof' in func_body or 'Array.isArray' in func_body)
        )
        
        # Pattern 5: for...in loop with recursive property copying
        # This is the classic vulnerable pattern: for (key in source) { if (isObject) { recursiveMerge(); } else { assign(); } }
        has_for_in_with_recursion = bool(
            re.search(r'for\s*\([^)]*\s+in\s+[^)]*\)', func_body, re.IGNORECASE) and
            has_type_check and
            re.search(r'\[[^\]]+\]\s*=\s*', func_body)
        )
        
        # Must have property copying AND recursive/nested handling
        has_property_copying = bool(
            re.search(r'\[[^\]]+\]\s*=\s*', func_body) or
            'Object.assign' in func_body or
            re.search(r'for\s*\([^)]*\s+in\s+[^)]*\)', func_body, re.IGNORECASE)
        )
        
        # Return true if it has recursive merge characteristics
        return (
            (has_for_in_with_recursion) or
            (has_nested_merge and has_property_copying) or
            (has_object_assign_with_nesting and has_property_copying) or
            (has_type_check and has_property_copying and 'for' in func_body.lower())
        )
    
    def _has_nested_object_merge_pattern(self, func_body: str) -> bool:
        """
        Check if function has patterns that indicate nested object merging.
        
        Args:
            func_body: Function body code
            
        Returns:
            True if nested object merge pattern is found
        """
        patterns = [
            # Pattern: if (target[key] != null && typeof target[key] === 'object') { merge(); }
            r'\[[^\]]+\]\s*!=\s*null',
            r'typeof\s+[^=]+\s*\[[^\]]+\]\s*===\s*["\']object["\']',
            # Pattern: Recursive call with nested property access
            r'\w+\s*\([^)]*\[[^\]]+\][^)]*\)',
            # Pattern: Deep copy/merge indicators
            r'deep',
            r'recursive',
        ]
        
        return any(
            re.search(pattern, func_body, re.IGNORECASE)
            for pattern in patterns
        )
    
    def _has_property_validation(self, func_body: str) -> bool:
        """
        Check if function body validates dangerous properties.
        
        Args:
            func_body: Function body code
            
        Returns:
            True if validation is present
        """
        validation_patterns = [
            # Explicit checks for dangerous properties
            r'key\s*[!=]==\s*["\']__proto__["\']',
            r'key\s*[!=]==\s*["\']constructor["\']',
            r'key\s*[!=]==\s*["\']prototype["\']',
            r'["\']__proto__["\']\s*[!=]==\s*key',
            r'["\']constructor["\']\s*[!=]==\s*key',
            r'["\']prototype["\']\s*[!=]==\s*key',
            # hasOwnProperty checks
            r'hasOwnProperty\s*\(\s*["\']__proto__["\']',
            r'hasOwnProperty\s*\(\s*["\']constructor["\']',
            r'hasOwnProperty\s*\(\s*["\']prototype["\']',
            # Object.prototype checks
            r'Object\.prototype\.hasOwnProperty',
            # Dangerous properties arrays/sets
            r'DANGEROUS_PROPERTIES',
            r'dangerousProperties',
            r'__proto__.*constructor.*prototype',
            # Continue/return statements that skip dangerous properties
            r'if\s*\([^)]*(?:__proto__|constructor|prototype)[^)]*\)\s*(?:continue|return)',
        ]
        
        return any(
            re.search(pattern, func_body, re.IGNORECASE)
            for pattern in validation_patterns
        )
    
    def _has_partial_validation(self, func_body: str) -> bool:
        """
        Check if function has partial validation (checks some but not all dangerous properties).
        
        Args:
            func_body: Function body code
            
        Returns:
            True if partial validation is present
        """
        # Check if it validates at least one dangerous property but not all
        checks_proto = bool(re.search(r'__proto__', func_body, re.IGNORECASE))
        checks_constructor = bool(re.search(r'constructor', func_body, re.IGNORECASE))
        checks_prototype = bool(re.search(r'\bprototype\b', func_body, re.IGNORECASE))
        
        # If it checks at least one but not all three, it's partial
        checked_count = sum([checks_proto, checks_constructor, checks_prototype])
        return 1 <= checked_count < 3
    
    
    def check_property_assignment(self, node: Dict[str, Any]) -> bool:
        """
        Check if a property assignment is potentially dangerous.
        
        Args:
            node: AST node representing a property assignment
            
        Returns:
            True if the assignment is potentially dangerous
        """
        prop_name = node.get("property", "")
        return prop_name in self.DANGEROUS_PROPERTIES
    
    def get_vulnerability_report(self) -> Dict[str, Any]:
        """
        Generate a detailed vulnerability report.
        
        Returns:
            Dictionary containing vulnerability statistics and details
        """
        return {
            "total_vulnerabilities": len(self.vulnerabilities),
            "by_severity": {
                "high": len([v for v in self.vulnerabilities if v.severity == "high"]),
                "medium": len([v for v in self.vulnerabilities if v.severity == "medium"]),
                "low": len([v for v in self.vulnerabilities if v.severity == "low"]),
            },
            "by_type": self._group_by_type(),
            "vulnerabilities": self.vulnerabilities,
        }
    
    def _group_by_type(self) -> Dict[str, int]:
        """
        Group vulnerabilities by type.
        
        Returns:
            Dictionary mapping vulnerability types to counts
        """
        type_counts = {}
        for vuln in self.vulnerabilities:
            vuln_type = vuln.vulnerability_type
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
        return type_counts
