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
    
    # Patterns that indicate potential pollution (unsafe merge/extend functions)
    POLLUTION_PATTERNS = [
        "merge",
        "extend",
        "clone",
        "assign",
        "deepCopy",
        "deepMerge",
        "deepExtend",
        "deepClone",
        "mixin",
        "copyProperties",
    ]
    
    # DOM methods that might retrieve user-controlled data
    DOM_DATA_METHODS = [
        "getAttribute",
        "getAttributeNode",
        "dataset",
        "querySelector",
        "getElementById",
        "getElementsByClassName",
    ]
    
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
        
        Args:
            ast: Parsed AST dictionary (from parser)
            
        Returns:
            List of detected vulnerabilities
        """
        self.vulnerabilities = []
        
        if self.verbose:
            print(f"Analyzing AST from {ast.get('file', 'unknown')}")
        
        file_type = ast.get("file_type", "javascript")
        
        # Analyze based on file type
        if file_type == "html":
            self._analyze_html_file(ast)
        else:
            self._analyze_javascript_code(ast)
        
        return self.vulnerabilities
    
    def _analyze_html_file(self, ast: Dict[str, Any]) -> None:
        """
        Analyze HTML file for prototype pollution via HTML injection.
        
        Args:
            ast: Parsed HTML AST dictionary
        """
        # Check for dangerous data attributes (like pace-js vulnerability)
        for data_attr in ast.get("data_attributes", []):
            if data_attr.get("dangerous"):
                self.vulnerabilities.append(Vulnerability(
                    severity="high",
                    line=data_attr.get("line", 0),
                    column=0,
                    message=(
                        f"HTML injection vector detected: data attribute '{data_attr['attribute']}' "
                        f"contains dangerous properties (__proto__, constructor, or prototype). "
                        f"This could lead to prototype pollution if parsed and merged without validation."
                    ),
                    code_snippet=f"{data_attr['attribute']}='{data_attr['value'][:100]}'",
                    vulnerability_type="html_injection_prototype_pollution",
                ))
            elif self._looks_like_options_attribute(data_attr.get("attribute", "")):
                # Check if this looks like a library options pattern (e.g., data-pace-options)
                self.vulnerabilities.append(Vulnerability(
                    severity="medium",
                    line=data_attr.get("line", 0),
                    column=0,
                    message=(
                        f"Potential HTML injection vector: data attribute '{data_attr['attribute']}' "
                        f"contains JSON that might be parsed and merged. Verify that the parsing code "
                        f"validates property names before merging."
                    ),
                    code_snippet=f"{data_attr['attribute']}='{data_attr['value'][:100]}'",
                    vulnerability_type="html_injection_suspicious",
                ))
        
        # Analyze inline JavaScript in HTML
        for inline_script in ast.get("inline_scripts", []):
            self._analyze_javascript_code(inline_script)
        
        # Analyze script tags for JSON.parse on DOM attributes
        for script_tag in ast.get("script_tags", []):
            script_content = script_tag.get("content", "")
            if script_content:
                self._check_json_parse_on_dom(script_content, script_tag.get("line", 0))
    
    def _looks_like_options_attribute(self, attr_name: str) -> bool:
        """
        Check if an attribute name looks like a library options pattern.
        
        This detects common patterns used by libraries to read configuration
        from HTML data attributes, which can be exploited for HTML injection.
        
        Args:
            attr_name: Attribute name to check
            
        Returns:
            True if it looks like an options attribute
        """
        patterns = [
            r"data-.*-options?$",      # data-pace-options, data-app-options
            r"data-options?$",          # data-options
            r"data-.*-config$",         # data-app-config
            r"data-config$",            # data-config
            r"data-.*-settings?$",      # data-app-settings
            r"data-settings?$",         # data-settings
            r"data-.*-params?$",        # data-app-params
            r"data-params?$",           # data-params
            r"data-.*-init$",           # data-app-init
            r"data-init$",              # data-init
        ]
        return any(re.match(pattern, attr_name, re.IGNORECASE) for pattern in patterns)
    
    def _analyze_javascript_code(self, ast: Dict[str, Any]) -> None:
        """
        Analyze JavaScript code for prototype pollution vulnerabilities.
        
        Args:
            ast: Parsed JavaScript AST dictionary
        """
        # Check for unsafe extend/merge functions
        functions = ast.get("functions", [])
        for func in functions:
            func_name = func.get("name") or ""
            if func_name and any(pattern.lower() in func_name.lower() for pattern in self.POLLUTION_PATTERNS):
                # This might be a merge/extend function - check if it's unsafe
                self._check_unsafe_merge_function(func, ast)
        
        # Check for direct dangerous property assignments
        assignments = ast.get("assignments", [])
        for assign in assignments:
            prop_name = assign.get("property", "")
            if prop_name in self.DANGEROUS_PROPERTIES:
                self.vulnerabilities.append(Vulnerability(
                    severity="high",
                    line=assign.get("line", 0),
                    column=assign.get("column", 0),
                    message=(
                        f"Direct assignment to dangerous property '{prop_name}'. "
                        f"This could lead to prototype pollution."
                    ),
                    code_snippet=assign.get("code", ""),
                    vulnerability_type="direct_dangerous_property_assignment",
                ))
        
        # Check for JSON.parse calls that might parse user-controlled data
        json_parse_calls = ast.get("json_parse_calls", [])
        for json_parse in json_parse_calls:
            self._check_json_parse_usage(json_parse, ast)
        
        # Check function calls for unsafe merge operations
        function_calls = ast.get("function_calls", [])
        for call in function_calls:
            func_name = call.get("function") or ""
            if func_name and any(pattern.lower() in func_name.lower() for pattern in self.POLLUTION_PATTERNS):
                # Check if this merge call might be using JSON.parse results
                call_code = call.get("code", "")
                is_using_json_parse = "JSON.parse" in call_code or any(
                    json_parse.get("line", 0) == call.get("line", 0) 
                    for json_parse in json_parse_calls
                )
                
                severity = "high" if is_using_json_parse else "medium"
                message = (
                    f"Call to merge/extend function '{func_name}' detected"
                )
                if is_using_json_parse:
                    message += " with potential JSON.parse input. This is a high-risk HTML injection vector."
                else:
                    message += ". Verify that it validates property names before merging."
                
                self.vulnerabilities.append(Vulnerability(
                    severity=severity,
                    line=call.get("line", 0),
                    column=call.get("column", 0),
                    message=message,
                    code_snippet=call.get("code", ""),
                    vulnerability_type="unsafe_merge_call" if not is_using_json_parse else "html_injection_merge_chain",
                ))
    
    def _check_unsafe_merge_function(self, func: Dict[str, Any], ast: Dict[str, Any]) -> None:
        """
        Check if a merge/extend function is unsafe (doesn't validate property names).
        
        Args:
            func: Function information dictionary
            ast: Full AST dictionary
        """
        func_name = func.get("name", "")
        func_line = func.get("line", 0)
        func_body = func.get("body", "")
        
        # Check if function body validates dangerous properties
        has_validation = False
        if func_body:
            # Look for checks for dangerous properties
            validation_patterns = [
                r'__proto__',
                r'constructor',
                r'prototype',
                r'hasOwnProperty',
                r'Object\.prototype',
            ]
            
            # Check if function checks for dangerous properties
            for pattern in validation_patterns:
                if re.search(pattern, func_body, re.IGNORECASE):
                    # Check if it's actually validating (not just using)
                    # Look for patterns like: if (key === '__proto__') or if (key !== '__proto__')
                    validation_checks = [
                        r'key\s*[!=]==\s*["\']__proto__["\']',
                        r'key\s*[!=]==\s*["\']constructor["\']',
                        r'key\s*[!=]==\s*["\']prototype["\']',
                        r'__proto__\s*in\s*',
                        r'hasOwnProperty\s*\(\s*["\']__proto__["\']',
                        r'hasOwnProperty\s*\(\s*["\']constructor["\']',
                        r'hasOwnProperty\s*\(\s*["\']prototype["\']',
                        r'dangerousProperties',
                        r'DANGEROUS_PROPERTIES',
                    ]
                    
                    for check_pattern in validation_checks:
                        if re.search(check_pattern, func_body, re.IGNORECASE):
                            has_validation = True
                            break
                    
                    if has_validation:
                        break
        
        # If no validation found, flag as vulnerable
        if not has_validation:
            self.vulnerabilities.append(Vulnerability(
                severity="high",
                line=func_line,
                column=func.get("column", 0),
                message=(
                    f"Unsafe merge/extend function '{func_name}' detected. "
                    f"This function does not validate property names (__proto__, "
                    f"constructor, prototype) before merging, making it vulnerable to "
                    f"prototype pollution attacks."
                ),
                code_snippet=func_body[:200] if func_body else f"function {func_name}(...)",
                vulnerability_type="unsafe_merge_function",
            ))
        else:
            # Still flag as potentially unsafe but lower severity
            self.vulnerabilities.append(Vulnerability(
                severity="medium",
                line=func_line,
                column=func.get("column", 0),
                message=(
                    f"Merge/extend function '{func_name}' detected with some validation. "
                    f"Please verify that all dangerous properties are properly checked."
                ),
                code_snippet=func_body[:200] if func_body else f"function {func_name}(...)",
                vulnerability_type="unsafe_merge_function",
            ))
    
    def _check_json_parse_usage(self, json_parse: Dict[str, Any], ast: Dict[str, Any]) -> None:
        """
        Check if JSON.parse is used in a potentially unsafe way.
        
        Args:
            json_parse: JSON.parse call information
            ast: Full AST dictionary
        """
        code_snippet = json_parse.get("code", "")
        line = json_parse.get("line", 0)
        
        # Check if JSON.parse is called on DOM attribute data
        # This covers various ways to get data from DOM elements
        dom_patterns = [
            r"\.getAttribute\s*\(",           # el.getAttribute("data-options")
            r"\.dataset\.",                   # el.dataset.options
            r"\.getAttributeNode\s*\(",        # el.getAttributeNode("data-options")
            r"querySelector",                 # document.querySelector("[data-options]")
            r"querySelectorAll",               # document.querySelectorAll("[data-options]")
            r"getElementById",                 # document.getElementById("data-options")
            r"getElementsByClassName",         # document.getElementsByClassName
            r"getElementsByTagName",           # document.getElementsByTagName
            r"\.innerHTML",                    # el.innerHTML (might contain JSON)
            r"\.textContent",                  # el.textContent (might contain JSON)
            r"\.innerText",                    # el.innerText (might contain JSON)
            r"\.value",                        # input.value (form data)
            r"localStorage\.getItem",          # localStorage.getItem (stored data)
            r"sessionStorage\.getItem",        # sessionStorage.getItem (stored data)
            r"location\.search",               # URL query parameters
            r"location\.hash",                 # URL hash
            r"URLSearchParams",                # URLSearchParams parsing
        ]
        
        is_dom_related = any(re.search(pattern, code_snippet, re.IGNORECASE) for pattern in dom_patterns)
        
        if is_dom_related:
            self.vulnerabilities.append(Vulnerability(
                severity="high",
                line=line,
                column=json_parse.get("column", 0),
                message=(
                    "JSON.parse() called on DOM attribute data. This is a common HTML injection "
                    "vector for prototype pollution (like pace-js vulnerability). "
                    "Ensure parsed data is validated before merging into objects."
                ),
                code_snippet=code_snippet,
                vulnerability_type="json_parse_dom_attribute",
            ))
        else:
            # Still potentially dangerous if the result is merged without validation
            self.vulnerabilities.append(Vulnerability(
                severity="medium",
                line=line,
                column=json_parse.get("column", 0),
                message=(
                    "JSON.parse() detected. If the parsed result is merged into objects without "
                    "validating property names, this could lead to prototype pollution."
                ),
                code_snippet=code_snippet,
                vulnerability_type="json_parse_suspicious",
            ))
    
    def _check_json_parse_on_dom(self, code: str, start_line: int) -> None:
        """
        Check for JSON.parse calls on DOM attributes in raw code.
        
        This detects HTML injection vectors where JSON.parse is used on
        user-controlled DOM data that could contain prototype pollution payloads.
        
        Args:
            code: JavaScript code string
            start_line: Starting line number
        """
        # Pattern to find JSON.parse(getAttribute(...)) or similar
        # These patterns indicate JSON.parse is being used on DOM data
        patterns = [
            r"JSON\.parse\s*\(\s*[^)]*\.getAttribute\s*\(",
            r"JSON\.parse\s*\(\s*[^)]*\.dataset\.",
            r"JSON\.parse\s*\(\s*[^)]*querySelector",
            r"JSON\.parse\s*\(\s*[^)]*getElementById",
            r"JSON\.parse\s*\(\s*[^)]*\.innerHTML",
            r"JSON\.parse\s*\(\s*[^)]*\.textContent",
            r"JSON\.parse\s*\(\s*[^)]*\.value",
            r"JSON\.parse\s*\(\s*[^)]*localStorage",
            r"JSON\.parse\s*\(\s*[^)]*sessionStorage",
            r"JSON\.parse\s*\(\s*[^)]*location\.search",
            r"JSON\.parse\s*\(\s*[^)]*location\.hash",
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, code, re.IGNORECASE):
                line_num = start_line + code[:match.start()].count("\n")
                self.vulnerabilities.append(Vulnerability(
                    severity="high",
                    line=line_num,
                    column=0,
                    message=(
                        "JSON.parse() called on DOM attribute data. This is a common HTML injection "
                        "vector for prototype pollution. Ensure parsed data validates property names "
                        "before merging into objects."
                    ),
                    code_snippet=code[max(0, match.start()-30):match.end()+30],
                    vulnerability_type="json_parse_dom_attribute",
                ))
    
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
    
    def check_merge_operation(self, node: Dict[str, Any]) -> bool:
        """
        Check if a merge/extend operation is vulnerable.
        
        Args:
            node: AST node representing a merge operation
            
        Returns:
            True if the operation is vulnerable
        """
        func_name = node.get("function", "")
        return any(pattern.lower() in func_name.lower() for pattern in self.POLLUTION_PATTERNS)
    
    def check_user_controlled_access(self, node: Dict[str, Any]) -> bool:
        """
        Check if property access uses user-controlled input.
        
        Args:
            node: AST node representing property access
            
        Returns:
            True if the access uses user-controlled input
        """
        # This would require more sophisticated taint analysis
        # For now, we check for common DOM methods
        code = node.get("code", "")
        return any(method in code for method in self.DOM_DATA_METHODS)
    
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
