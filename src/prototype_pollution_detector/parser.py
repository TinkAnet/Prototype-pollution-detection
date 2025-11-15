"""
JavaScript and HTML parser module for extracting AST and code structure.

This module provides functionality to parse JavaScript code and HTML files
to extract relevant information for prototype pollution detection.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

try:
    import esprima
except ImportError:
    esprima = None

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None


class JavaScriptParser:
    """
    Parser for JavaScript code and HTML files.
    
    This class handles parsing JavaScript files, HTML files, and extracting
    abstract syntax tree (AST) information for prototype pollution detection.
    """
    
    def __init__(self, verbose: bool = False):
        """
        Initialize the parser.
        
        Args:
            verbose: Enable verbose output
        """
        self.verbose = verbose
        if esprima is None:
            if verbose:
                print("Warning: esprima not installed. JavaScript parsing will be limited.")
        if BeautifulSoup is None:
            if verbose:
                print("Warning: beautifulsoup4 not installed. HTML parsing will be limited.")
    
    def parse_file(self, file_path: Path) -> Dict[str, Any]:
        """
        Parse a JavaScript or HTML file and return its AST representation.
        
        Args:
            file_path: Path to the JavaScript or HTML file
            
        Returns:
            Dictionary containing parsed AST and metadata
            
        Raises:
            FileNotFoundError: If the file doesn't exist
            ValueError: If the file cannot be parsed
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        if self.verbose:
            print(f"Parsing file: {file_path}")
        
        # Handle HTML files
        if file_path.suffix in {".html", ".htm"}:
            return self._parse_html_file(file_path)
        
        # Handle JavaScript files
        if file_path.suffix in {".js", ".jsx", ".mjs", ".cjs"}:
            return self._parse_js_file(file_path)
        
        # Default: try to parse as JavaScript
        return self._parse_js_file(file_path)
    
    def _parse_html_file(self, file_path: Path) -> Dict[str, Any]:
        """
        Parse an HTML file and extract JavaScript code and data attributes.
        
        Args:
            file_path: Path to the HTML file
            
        Returns:
            Dictionary containing parsed information
        """
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        
        result = {
            "file": str(file_path),
            "file_type": "html",
            "ast": None,
            "functions": [],
            "assignments": [],
            "property_accesses": [],
            "script_tags": [],
            "data_attributes": [],
            "inline_scripts": [],
        }
        
        if BeautifulSoup is None:
            # Fallback: basic regex parsing
            return self._parse_html_regex(content, result)
        
        try:
            soup = BeautifulSoup(content, "lxml")
            
            # Extract script tags
            script_tags = soup.find_all("script")
            for script in script_tags:
                script_content = script.string
                if script_content:
                    script_info = {
                        "type": script.get("type", "text/javascript"),
                        "src": script.get("src"),
                        "content": script_content,
                        "line": getattr(script, "sourceline", None),
                    }
                    result["script_tags"].append(script_info)
                    
                    # Parse inline JavaScript
                    if script_content.strip():
                        try:
                            js_ast = self.parse_code(script_content, f"{file_path}:script")
                            result["inline_scripts"].append(js_ast)
                        except Exception as e:
                            if self.verbose:
                                print(f"Warning: Could not parse inline script: {e}")
            
            # Extract ALL attributes that might contain JSON (general HTML injection detection)
            # This is more general than just looking for specific patterns - we check everything
            all_elements = soup.find_all(True)  # Find all elements
            for element in all_elements:
                for attr_name, attr_value in element.attrs.items():
                    if isinstance(attr_value, str) and len(attr_value.strip()) > 0:
                        # Check if attribute value looks like JSON (potential injection vector)
                        # We check ALL attributes, not just data-* or specific patterns
                        looks_like_json = self._looks_like_json(attr_value)
                        contains_dangerous_strings = any(
                            prop in attr_value for prop in ["__proto__", "constructor", "prototype"]
                        )
                        
                        # Flag if it's JSON or contains dangerous strings
                        # This catches ANY attribute that could be exploited
                        if looks_like_json or contains_dangerous_strings:
                            data_info = {
                                "element": element.name,
                                "attribute": attr_name,
                                "value": attr_value,
                                "id": element.get("id"),
                                "line": getattr(element, "sourceline", None),
                                "is_json": looks_like_json,
                            }
                            
                            # Try to parse as JSON to check for dangerous properties
                            if looks_like_json:
                                try:
                                    parsed_json = json.loads(attr_value)
                                    if self._contains_dangerous_properties(parsed_json):
                                        data_info["dangerous"] = True
                                except (json.JSONDecodeError, TypeError):
                                    # Invalid JSON but might still be dangerous
                                    if contains_dangerous_strings:
                                        data_info["dangerous"] = True
                                        data_info["invalid_json"] = True
                            elif contains_dangerous_strings:
                                # Not JSON but contains dangerous strings
                                data_info["dangerous"] = True
                                data_info["contains_dangerous_strings"] = True
                            
                            result["data_attributes"].append(data_info)
            
            # Parse all JavaScript code found
            all_js_code = "\n".join([s.string for s in script_tags if s.string])
            if all_js_code:
                try:
                    js_result = self.parse_code(all_js_code, str(file_path))
                    result["ast"] = js_result.get("ast")
                    result["functions"] = js_result.get("functions", [])
                    result["assignments"] = js_result.get("assignments", [])
                    result["property_accesses"] = js_result.get("property_accesses", [])
                except Exception as e:
                    if self.verbose:
                        print(f"Warning: Could not parse JavaScript from HTML: {e}")
        
        except Exception as e:
            if self.verbose:
                print(f"Warning: Error parsing HTML with BeautifulSoup: {e}")
            return self._parse_html_regex(content, result)
        
        return result
    
    def _parse_html_regex(self, content: str, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Fallback HTML parsing using regex when BeautifulSoup is not available.
        
        Args:
            content: HTML content
            result: Result dictionary to populate
            
        Returns:
            Updated result dictionary
        """
        # Extract script tags
        script_pattern = r'<script[^>]*>(.*?)</script>'
        scripts = re.finditer(script_pattern, content, re.DOTALL | re.IGNORECASE)
        for match in scripts:
            script_content = match.group(1)
            if script_content.strip():
                result["script_tags"].append({
                    "content": script_content,
                    "line": content[:match.start()].count("\n") + 1,
                })
                try:
                    js_ast = self.parse_code(script_content, result["file"])
                    result["inline_scripts"].append(js_ast)
                except Exception:
                    pass
        
        # Extract ALL attributes that might contain JSON or dangerous strings
        # General pattern: any-attribute="value" - we check everything
        # This is more general than just data-* attributes
        attr_pattern = r'(\w+)=["\']([^"\']+)["\']'
        attr_matches = re.finditer(attr_pattern, content)
        for match in attr_matches:
            attr_name = match.group(1)
            attr_value = match.group(2)
            
            # Check if value looks like JSON or contains dangerous strings
            # We check ALL attributes, not just specific ones
            looks_like_json = self._looks_like_json(attr_value)
            contains_dangerous = any(
                prop in attr_value for prop in ["__proto__", "constructor", "prototype"]
            )
            
            if looks_like_json or contains_dangerous:
                data_info = {
                    "attribute": attr_name,
                    "value": attr_value,
                    "line": content[:match.start()].count("\n") + 1,
                    "is_json": looks_like_json,
                }
                
                # Check for dangerous properties
                if looks_like_json:
                    try:
                        parsed_json = json.loads(attr_value)
                        if self._contains_dangerous_properties(parsed_json):
                            data_info["dangerous"] = True
                    except (json.JSONDecodeError, TypeError):
                        if contains_dangerous:
                            data_info["dangerous"] = True
                            data_info["invalid_json"] = True
                elif contains_dangerous:
                    data_info["dangerous"] = True
                    data_info["contains_dangerous_strings"] = True
                
                result["data_attributes"].append(data_info)
        
        return result
    
    def _looks_like_json(self, value: str) -> bool:
        """
        Check if a string looks like JSON.
        
        Args:
            value: String to check
            
        Returns:
            True if it looks like JSON
        """
        value = value.strip()
        return (
            (value.startswith("{") and value.endswith("}")) or
            (value.startswith("[") and value.endswith("]"))
        )
    
    def _contains_dangerous_properties(self, obj: Any, path: str = "") -> bool:
        """
        Recursively check if an object contains dangerous properties.
        
        Args:
            obj: Object to check
            path: Current path in the object
            
        Returns:
            True if dangerous properties are found
        """
        dangerous = {"__proto__", "constructor", "prototype"}
        
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key in dangerous:
                    return True
                if isinstance(value, (dict, list)):
                    if self._contains_dangerous_properties(value, f"{path}.{key}"):
                        return True
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                if isinstance(item, (dict, list)):
                    if self._contains_dangerous_properties(item, f"{path}[{i}]"):
                        return True
        
        return False
    
    def _parse_js_file(self, file_path: Path) -> Dict[str, Any]:
        """
        Parse a JavaScript file.
        
        Args:
            file_path: Path to the JavaScript file
            
        Returns:
            Dictionary containing parsed AST and metadata
        """
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        return self.parse_code(content, str(file_path))
    
    def parse_code(self, code: str, filename: str = "<string>") -> Dict[str, Any]:
        """
        Parse JavaScript code from a string.
        
        Args:
            code: JavaScript code as a string
            filename: Optional filename for error reporting
            
        Returns:
            Dictionary containing parsed AST and metadata
        """
        if self.verbose:
            print(f"Parsing code from {filename}")
        
        result = {
            "file": filename,
            "ast": None,
            "functions": [],
            "assignments": [],
            "property_accesses": [],
            "function_calls": [],
            "json_parse_calls": [],
        }
        
        if esprima is None:
            # Fallback: basic pattern matching
            return self._parse_code_regex(code, result)
        
        parse_kwargs = {"loc": True, "range": True, "tolerant": True}

        def _parse_with_module_fallback() -> Any:
            """Try parseScript first, then fall back to parseModule."""
            try:
                return esprima.parseScript(code, **parse_kwargs)
            except Exception as script_err:  # SyntaxError from esprima
                try:
                    return esprima.parseModule(code, **parse_kwargs)
                except Exception:
                    raise script_err

        try:
            # Parse with esprima (script first, module fallback)
            ast_obj = _parse_with_module_fallback()
            
            # Convert esprima AST object to dict if needed
            if hasattr(ast_obj, 'toDict'):
                ast = ast_obj.toDict()
            elif hasattr(ast_obj, '__dict__'):
                # Try to convert to dict manually
                ast = self._esprima_to_dict(ast_obj)
            else:
                # Assume it's already a dict-like structure
                ast = ast_obj
            
            result["ast"] = ast
            
            # Extract useful information from AST
            self._extract_from_ast(ast, code, result)
        
        except Exception as e:
            if self.verbose:
                print(f"Warning: Could not parse JavaScript with esprima: {e}")
            return self._parse_code_regex(code, result)
        
        return result
    
    def _esprima_to_dict(self, obj: Any) -> Any:
        """
        Convert esprima AST object to dictionary.
        
        Args:
            obj: Esprima AST object
            
        Returns:
            Dictionary representation
        """
        if isinstance(obj, (str, int, float, bool, type(None))):
            return obj
        elif isinstance(obj, list):
            return [self._esprima_to_dict(item) for item in obj]
        elif hasattr(obj, '__dict__'):
            result = {}
            for key, value in obj.__dict__.items():
                if not key.startswith('_'):
                    result[key] = self._esprima_to_dict(value)
            return result
        else:
            return obj
    
    def _extract_from_ast(self, ast: Dict[str, Any], code: str, result: Dict[str, Any]) -> None:
        """
        Extract relevant information from the AST.
        
        Args:
            ast: Parsed AST
            code: Original source code
            result: Result dictionary to populate
        """
        def traverse(node: Any, parent: Optional[Any] = None) -> None:
            """Recursively traverse the AST."""
            if not isinstance(node, dict):
                return
            
            node_type = node.get("type")
            
            # Extract function declarations
            if node_type == "FunctionDeclaration":
                func_body = node.get("body", {})
                func_info = {
                    "name": node.get("id", {}).get("name"),
                    "params": [p.get("name") for p in node.get("params", [])],
                    "line": node.get("loc", {}).get("start", {}).get("line"),
                    "column": node.get("loc", {}).get("start", {}).get("column"),
                    "body": self._get_code_snippet(func_body, code) if func_body else "",
                    "ast_node": node,  # Include full AST node for semantic analysis
                }
                result["functions"].append(func_info)
            
            # Extract function expressions
            elif node_type == "FunctionExpression":
                func_body = node.get("body", {})
                func_info = {
                    "name": node.get("id", {}).get("name"),
                    "params": [p.get("name") for p in node.get("params", [])],
                    "line": node.get("loc", {}).get("start", {}).get("line"),
                    "column": node.get("loc", {}).get("start", {}).get("column"),
                    "body": self._get_code_snippet(func_body, code) if func_body else "",
                    "ast_node": node,  # Include full AST node for semantic analysis
                }
                result["functions"].append(func_info)
            
            # Extract assignments
            elif node_type == "AssignmentExpression":
                left = node.get("left", {})
                if left.get("type") == "MemberExpression":
                    # Check for nested property access (e.g., obj.__proto__.polluted)
                    prop_name = self._get_property_name(left)
                    if prop_name:
                        assign_info = {
                            "property": prop_name,
                            "line": node.get("loc", {}).get("start", {}).get("line"),
                            "column": node.get("loc", {}).get("start", {}).get("column"),
                            "code": self._get_code_snippet(node, code),
                        }
                        result["assignments"].append(assign_info)
                    # Also check for nested dangerous properties
                    nested_prop = self._get_nested_dangerous_property(left)
                    if nested_prop:
                        assign_info = {
                            "property": nested_prop,
                            "line": node.get("loc", {}).get("start", {}).get("line"),
                            "column": node.get("loc", {}).get("start", {}).get("column"),
                            "code": self._get_code_snippet(node, code),
                        }
                        result["assignments"].append(assign_info)
            
            # Extract property access
            elif node_type == "MemberExpression":
                prop_name = self._get_property_name(node)
                access_info = {
                    "property": prop_name,
                    "line": node.get("loc", {}).get("start", {}).get("line"),
                    "column": node.get("loc", {}).get("start", {}).get("column"),
                }
                result["property_accesses"].append(access_info)
            
            # Extract function calls
            elif node_type == "CallExpression":
                callee = node.get("callee", {})
                func_name = self._get_function_name(callee)
                call_info = {
                    "function": func_name,
                    "line": node.get("loc", {}).get("start", {}).get("line"),
                    "column": node.get("loc", {}).get("start", {}).get("column"),
                    "arguments": len(node.get("arguments", [])),
                    "code": self._get_code_snippet(node, code),
                }
                result["function_calls"].append(call_info)
                
                # Check for JSON.parse calls
                if func_name == "JSON.parse":
                    json_parse_info = {
                        "line": node.get("loc", {}).get("start", {}).get("line"),
                        "column": node.get("loc", {}).get("start", {}).get("column"),
                        "code": self._get_code_snippet(node, code),
                    }
                    result["json_parse_calls"].append(json_parse_info)
            
            # Recursively traverse children
            for key, value in node.items():
                if key in ("loc", "range", "leadingComments", "trailingComments"):
                    continue
                if isinstance(value, dict):
                    traverse(value, node)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            traverse(item, node)
        
        traverse(ast)
    
    def _get_property_name(self, node: Dict[str, Any]) -> Optional[str]:
        """
        Extract property name from a MemberExpression node.
        
        Args:
            node: AST node
            
        Returns:
            Property name or None
        """
        prop = node.get("property", {})
        if prop.get("type") == "Identifier":
            return prop.get("name")
        elif prop.get("type") == "Literal":
            return str(prop.get("value"))
        return None
    
    def _get_function_name(self, node: Dict[str, Any]) -> Optional[str]:
        """
        Extract function name from a CallExpression callee.
        
        Args:
            node: AST node
            
        Returns:
            Function name or None
        """
        if node.get("type") == "Identifier":
            return node.get("name")
        elif node.get("type") == "MemberExpression":
            obj = node.get("object", {})
            prop = node.get("property", {})
            if obj.get("type") == "Identifier" and prop.get("type") == "Identifier":
                return f"{obj.get('name')}.{prop.get('name')}"
        return None
    
    def _get_nested_dangerous_property(self, node: Dict[str, Any]) -> Optional[str]:
        """
        Check for nested dangerous property access (e.g., obj.__proto__.polluted).
        
        Args:
            node: MemberExpression AST node
            
        Returns:
            Dangerous property name if found, None otherwise
        """
        dangerous = {"__proto__", "constructor", "prototype"}
        
        if node.get("type") != "MemberExpression":
            return None
        
        # Check current property
        prop = node.get("property", {})
        prop_name = None
        
        if prop.get("type") == "Identifier":
            prop_name = prop.get("name")
        elif prop.get("type") == "Literal":
            prop_name = str(prop.get("value"))
        
        if prop_name in dangerous:
            return prop_name
        
        # Check nested object (recursively)
        obj = node.get("object", {})
        if obj.get("type") == "MemberExpression":
            nested_prop = self._get_nested_dangerous_property(obj)
            if nested_prop:
                return nested_prop
        
        return None
    
    def _get_code_snippet(self, node: Dict[str, Any], code: str) -> str:
        """
        Extract code snippet for a node.
        
        Args:
            node: AST node
            code: Original source code
            
        Returns:
            Code snippet string
        """
        if "range" in node:
            start, end = node["range"]
            return code[start:end]
        return ""
    
    def _parse_code_regex(self, code: str, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Minimal fallback parsing when esprima is not available.
        
        Note: This only extracts minimal information. Full semantic analysis
        requires AST parsing and will not be available when using this fallback.
        
        Args:
            code: JavaScript code
            result: Result dictionary to populate
            
        Returns:
            Updated result dictionary
        """
        # Minimal extraction - no regex-based analysis
        # Just mark that AST parsing failed
        result["parse_error"] = "esprima not available - AST parsing required for semantic analysis"
        
        return result
    
    def extract_property_assignments(self, ast: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract property assignment expressions from the AST.
        
        Args:
            ast: Parsed AST dictionary
            
        Returns:
            List of property assignment nodes
        """
        if ast is None:
            return []
        
        assignments = []
        if isinstance(ast, dict) and "assignments" in ast:
            assignments = ast["assignments"]
        
        return assignments
    
    def extract_function_calls(self, ast: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract function call expressions from the AST.
        
        Args:
            ast: Parsed AST dictionary
            
        Returns:
            List of function call nodes
        """
        if ast is None:
            return []
        
        calls = []
        if isinstance(ast, dict):
            if "function_calls" in ast:
                calls = ast["function_calls"]
            elif "ast" in ast:
                # Try to extract from nested AST
                return self.extract_function_calls(ast["ast"])
        
        return calls
