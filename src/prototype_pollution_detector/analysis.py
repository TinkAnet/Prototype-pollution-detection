"""
Analysis module for detecting prototype pollution patterns.

This module contains the core logic for analyzing parsed JavaScript code
and HTML files to identify potential prototype pollution vulnerabilities.
Uses semantic AST analysis instead of regex pattern matching.
"""

from typing import Dict, List, Any, Optional
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
        self.sources: List[Dict[str, Any]] = []  # Track data sources
        self.data_flow: Dict[str, List[str]] = {}  # Track variable assignments
    
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
                    # If parsing fails, skip this script (no regex fallback)
                    if self.verbose:
                        print(f"Warning: Could not parse script tag at line {script_tag.get('line', 'unknown')}")
    
    
    def _analyze_javascript_code(self, ast: Dict[str, Any]) -> None:
        """
        Analyze ALL functions in JavaScript code for prototype pollution vulnerabilities.
        
        Checks every function to see if its logic is vulnerable, not just functions
        with suspicious names. Now includes source detection and data flow tracking.
        
        Args:
            ast: Parsed JavaScript AST dictionary
        """
        # Reset tracking for new AST
        self.sources = []
        self.data_flow = {}
        
        # Step 1: Detect sources (JSON.parse, DOM attributes, user input)
        self._detect_sources(ast)
        
        # Step 2: Track data flow (variable assignments)
        self._track_data_flow(ast)
        
        # Step 3: Analyze ALL functions for vulnerabilities
        functions = ast.get("functions", [])
        for func in functions:
            # Check if this function's logic is vulnerable to prototype pollution
            self._check_function_vulnerability(func, ast)
        
        # Step 4: Check for direct dangerous property assignments
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
    
    def _detect_sources(self, ast: Dict[str, Any]) -> None:
        """
        Detect data sources that could contain user-controlled input.
        
        Sources include:
        - JSON.parse() calls
        - DOM attribute parsing (getAttribute, dataset, etc.)
        - User input handling (form inputs, etc.)
        
        Args:
            ast: Parsed AST dictionary
        """
        ast_root = ast.get("ast")
        if not ast_root:
            return
        
        self._find_sources_in_ast(ast_root)
        
        # Also check json_parse_calls extracted by parser
        for json_call in ast.get("json_parse_calls", []):
            self.sources.append({
                "type": "json_parse",
                "line": json_call.get("line"),
                "column": json_call.get("column"),
                "code": json_call.get("code", ""),
                "variable": None,  # Will be extracted from AST
            })
    
    def _find_sources_in_ast(self, node: Any) -> None:
        """
        Recursively find source nodes in AST.
        
        Args:
            node: AST node to analyze
        """
        if not isinstance(node, dict):
            return
        
        node_type = node.get("type")
        
        # Detect JSON.parse() calls
        if node_type == "CallExpression":
            callee = node.get("callee", {})
            callee_name = self._get_function_name_from_ast(callee)
            
            if callee_name == "JSON.parse":
                # Find the variable this is assigned to
                variable_name = self._get_assigned_variable(node)
                source_info = {
                    "type": "json_parse",
                    "line": node.get("loc", {}).get("start", {}).get("line"),
                    "column": node.get("loc", {}).get("start", {}).get("column"),
                    "variable": variable_name,
                    "node": node,
                }
                self.sources.append(source_info)
            
            # Detect DOM attribute access patterns
            elif callee_name and ("getAttribute" in callee_name or "dataset" in callee_name):
                variable_name = self._get_assigned_variable(node)
                source_info = {
                    "type": "dom_attribute",
                    "line": node.get("loc", {}).get("start", {}).get("line"),
                    "column": node.get("loc", {}).get("start", {}).get("column"),
                    "variable": variable_name,
                    "method": callee_name,
                    "node": node,
                }
                self.sources.append(source_info)
            
            # Detect querySelector/querySelectorAll (often used with getAttribute)
            elif callee_name and "querySelector" in callee_name:
                # Check if result is used with getAttribute
                variable_name = self._get_assigned_variable(node)
                if variable_name:
                    source_info = {
                        "type": "dom_query",
                        "line": node.get("loc", {}).get("start", {}).get("line"),
                        "column": node.get("loc", {}).get("start", {}).get("column"),
                        "variable": variable_name,
                        "method": callee_name,
                        "node": node,
                    }
                    self.sources.append(source_info)
        
        # Detect form input access
        elif node_type == "MemberExpression":
            prop_name = self._get_property_name_from_ast(node)
            if prop_name in ("value", "textContent", "innerHTML"):
                # Check if accessing form element
                obj_name = self._get_object_name_from_ast(node)
                if obj_name:
                    variable_name = self._get_assigned_variable(node)
                    source_info = {
                        "type": "user_input",
                        "line": node.get("loc", {}).get("start", {}).get("line"),
                        "column": node.get("loc", {}).get("start", {}).get("column"),
                        "variable": variable_name,
                        "property": prop_name,
                        "object": obj_name,
                        "node": node,
                    }
                    self.sources.append(source_info)
        
        # Recursively search children
        for key, value in node.items():
            if key in ("loc", "range", "leadingComments", "trailingComments"):
                continue
            if isinstance(value, dict):
                self._find_sources_in_ast(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        self._find_sources_in_ast(item)
    
    def _get_assigned_variable(self, node: Any, parent: Optional[Any] = None) -> Optional[str]:
        """
        Get the variable name that a node is assigned to.
        
        Args:
            node: AST node (usually a CallExpression)
            parent: Parent node (for context)
            
        Returns:
            Variable name or None
        """
        # This method is called during AST traversal, so we need to check
        # if the node is part of a VariableDeclarator or AssignmentExpression
        # We'll extract this during the traversal in _extract_variable_assignments
        # For now, return None - the actual extraction happens in _extract_variable_assignments
        return None
    
    def _get_object_name_from_ast(self, member_expr: Dict[str, Any]) -> Optional[str]:
        """
        Get the object name from a MemberExpression.
        
        Args:
            member_expr: MemberExpression AST node
            
        Returns:
            Object name or None
        """
        if member_expr.get("type") != "MemberExpression":
            return None
        
        obj = member_expr.get("object", {})
        if obj.get("type") == "Identifier":
            return obj.get("name")
        elif obj.get("type") == "MemberExpression":
            # Recursive member access like document.getElementById
            return self._get_object_name_from_ast(obj)
        
        return None
    
    def _track_data_flow(self, ast: Dict[str, Any]) -> None:
        """
        Track data flow by analyzing variable assignments.
        
        This builds a map of which variables are assigned from sources.
        
        Args:
            ast: Parsed AST dictionary
        """
        ast_root = ast.get("ast")
        if not ast_root:
            return
        
        self._extract_variable_assignments(ast_root)
    
    def _extract_variable_assignments(self, node: Any) -> None:
        """
        Extract variable assignments to track data flow.
        
        Args:
            node: AST node to analyze
        """
        if not isinstance(node, dict):
            return
        
        node_type = node.get("type")
        
        # Track variable declarations: var x = JSON.parse(...)
        if node_type == "VariableDeclarator":
            var_id = node.get("id", {})
            init = node.get("init", {})
            
            if var_id.get("type") == "Identifier":
                var_name = var_id.get("name")
                
                # Check if init is a source
                if init.get("type") == "CallExpression":
                    callee = init.get("callee", {})
                    callee_name = self._get_function_name_from_ast(callee)
                    
                    if callee_name == "JSON.parse":
                        if var_name not in self.data_flow:
                            self.data_flow[var_name] = []
                        self.data_flow[var_name].append("json_parse")
                        # Update source with variable name
                        self._update_source_variable(init, var_name)
                    
                    elif callee_name and ("getAttribute" in callee_name or "dataset" in callee_name):
                        if var_name not in self.data_flow:
                            self.data_flow[var_name] = []
                        self.data_flow[var_name].append("dom_attribute")
                        self._update_source_variable(init, var_name)
                    
                    elif callee_name and "querySelector" in callee_name:
                        if var_name not in self.data_flow:
                            self.data_flow[var_name] = []
                        self.data_flow[var_name].append("dom_query")
                        self._update_source_variable(init, var_name)
                
                # Check for nested patterns like: var x = element.getAttribute('data')
                elif init.get("type") == "MemberExpression":
                    # This handles cases like: var x = el.getAttribute('data')
                    obj = init.get("object", {})
                    prop = init.get("property", {})
                    if prop.get("type") == "Identifier" and prop.get("name") in ("getAttribute", "dataset"):
                        if var_name not in self.data_flow:
                            self.data_flow[var_name] = []
                        self.data_flow[var_name].append("dom_attribute")
        
        # Track assignment expressions: x = JSON.parse(...)
        elif node_type == "AssignmentExpression":
            left = node.get("left", {})
            right = node.get("right", {})
            
            if left.get("type") == "Identifier":
                var_name = left.get("name")
                
                # Check if right side is a source
                if right.get("type") == "CallExpression":
                    callee = right.get("callee", {})
                    callee_name = self._get_function_name_from_ast(callee)
                    
                    if callee_name == "JSON.parse":
                        if var_name not in self.data_flow:
                            self.data_flow[var_name] = []
                        self.data_flow[var_name].append("json_parse")
                        self._update_source_variable(right, var_name)
                    
                    elif callee_name and ("getAttribute" in callee_name or "dataset" in callee_name):
                        if var_name not in self.data_flow:
                            self.data_flow[var_name] = []
                        self.data_flow[var_name].append("dom_attribute")
                        self._update_source_variable(right, var_name)
        
        # Recursively search children
        for key, value in node.items():
            if key in ("loc", "range", "leadingComments", "trailingComments"):
                continue
            if isinstance(value, dict):
                self._extract_variable_assignments(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        self._extract_variable_assignments(item)
    
    def _update_source_variable(self, node: Any, var_name: str) -> None:
        """
        Update source entry with variable name.
        
        Args:
            node: Source node (CallExpression)
            var_name: Variable name it's assigned to
        """
        node_line = node.get("loc", {}).get("start", {}).get("line")
        for source in self.sources:
            if source.get("line") == node_line and source.get("variable") is None:
                source["variable"] = var_name
                break
    
    def _check_function_vulnerability(self, func: Dict[str, Any], ast: Dict[str, Any]) -> None:
        """
        Check if a function's logic is vulnerable to prototype pollution using semantic AST analysis.
        
        Focus: Detects recursive/deep merge functions that are vulnerable.
        Prototype pollution typically occurs in recursive merge functions that
        traverse nested objects without validating dangerous properties.
        
        Args:
            func: Function information dictionary
            ast: Full AST dictionary
        """
        func_name = func.get("name", "") or ""
        func_line = func.get("line", 0) or 0
        func_column = func.get("column", 0) or 0
        
        # Get the function's AST node if available
        func_ast = func.get("ast_node")
        if not func_ast:
            # Try to find function in main AST
            func_ast = self._find_function_in_ast(ast, func_name, func_line)
        
        if not func_ast:
            return
        
        # Analyze function semantically using AST
        analysis_result = self._analyze_function_ast(func_ast, func_name, ast)
        
        if analysis_result["is_vulnerable"]:
            func_display_name = func_name if func_name else "(anonymous)"
            severity = analysis_result.get("severity", "high")
            
            # Enhance message with source information if available
            source_info = analysis_result.get("source_info")
            if source_info:
                message = (
                    f"Function '{func_display_name}' performs property copying/merging "
                    f"with data from {source_info['type']} source (line {source_info['line']}) "
                    f"without validating dangerous properties. This creates a prototype pollution vulnerability."
                )
            else:
                message = analysis_result.get("message", 
                    f"Function '{func_display_name}' is vulnerable to prototype pollution.")
            
            code_snippet = func.get("body", "")[:300] if func.get("body") else ""
            
            self.vulnerabilities.append(Vulnerability(
                severity=severity,
                line=func_line,
                column=func_column,
                message=message,
                code_snippet=code_snippet,
                vulnerability_type=analysis_result.get("vulnerability_type", "vulnerable_function"),
            ))
    
    def _find_function_in_ast(self, ast: Dict[str, Any], func_name: str, line: int) -> Optional[Dict[str, Any]]:
        """
        Find a function node in the AST by name and line number.
        
        Args:
            ast: AST dictionary
            func_name: Function name
            line: Line number
            
        Returns:
            Function AST node or None
        """
        ast_root = ast.get("ast")
        if not ast_root:
            return None
        
        return self._traverse_ast_for_function(ast_root, func_name, line)
    
    def _traverse_ast_for_function(self, node: Any, func_name: str, line: int) -> Optional[Dict[str, Any]]:
        """
        Traverse AST to find a function node.
        
        Args:
            node: AST node
            func_name: Function name to find
            line: Line number
            
        Returns:
            Function node or None
        """
        if not isinstance(node, dict):
            return None
        
        node_type = node.get("type")
        node_line = node.get("loc", {}).get("start", {}).get("line")
        
        if node_type in ("FunctionDeclaration", "FunctionExpression"):
            func_id = node.get("id", {})
            if func_id and func_id.get("name") == func_name:
                if node_line == line or line == 0:
                    return node
        
        # Recursively search children
        for key, value in node.items():
            if key in ("loc", "range", "leadingComments", "trailingComments"):
                continue
            if isinstance(value, dict):
                result = self._traverse_ast_for_function(value, func_name, line)
                if result:
                    return result
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        result = self._traverse_ast_for_function(item, func_name, line)
                        if result:
                            return result
        
        return None
    
    def _analyze_function_ast(self, func_node: Dict[str, Any], func_name: str, ast: Dict[str, Any]) -> Dict[str, Any]:
        """
        Semantically analyze a function AST node for prototype pollution vulnerabilities.
        
        This method detects sinks (dangerous operations) and checks if source data reaches them.
        
        Args:
            func_node: Function AST node
            func_name: Function name
            ast: Full AST dictionary
            
        Returns:
            Dictionary with analysis results including source-sink relationships
        """
        result = {
            "is_vulnerable": False,
            "severity": "low",
            "message": "",
            "vulnerability_type": "",
            "source_info": None,
        }
        
        func_body = func_node.get("body", {})
        if not func_body:
            return result
        
        # Get function parameters (potential sources)
        func_params = func_node.get("params", [])
        param_names = [p.get("name") for p in func_params if p.get("type") == "Identifier"]
        
        # Analyze function body semantically
        sink_analysis = self._find_prototype_pollution_sinks(func_body, func_name)
        
        if sink_analysis["has_sink"]:
            has_validation = sink_analysis["has_validation"]
            is_recursive = sink_analysis["is_recursive"]
            
            # Check if source data flows to this function
            source_info = self._check_source_to_sink_flow(func_body, param_names, ast)
            
            if not has_validation:
                result["is_vulnerable"] = True
                result["severity"] = "high" if source_info else "high"
                result["vulnerability_type"] = "vulnerable_recursive_merge" if is_recursive else "vulnerable_property_assignment"
                result["source_info"] = source_info
                
                if source_info:
                    result["vulnerability_type"] = "source_to_sink_pollution"
                    result["message"] = (
                        f"Function '{func_name if func_name else '(anonymous)'}' receives data from "
                        f"{source_info['type']} source and performs property copying/merging "
                        f"without validating dangerous properties. This creates a prototype pollution vulnerability."
                    )
                else:
                    result["message"] = (
                        f"Function '{func_name if func_name else '(anonymous)'}' performs property copying/merging "
                        f"without validating dangerous properties (__proto__, constructor, prototype). "
                        f"This makes it vulnerable to prototype pollution attacks."
                    )
            elif sink_analysis["has_partial_validation"]:
                result["is_vulnerable"] = True
                result["severity"] = "medium"
                result["vulnerability_type"] = "partially_safe_recursive_merge"
                result["source_info"] = source_info
                result["message"] = (
                    f"Function '{func_name if func_name else '(anonymous)'}' performs deep property copying "
                    f"with partial validation. Please verify that all dangerous properties "
                    f"are properly checked before recursive merging."
                )
        
        return result
    
    def _check_source_to_sink_flow(self, func_body: Any, param_names: List[str], ast: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Check if source data flows to sinks in the function.
        
        Args:
            func_body: Function body AST node
            param_names: List of function parameter names
            ast: Full AST dictionary
            
        Returns:
            Source information if flow detected, None otherwise
        """
        # Check if any parameter comes from a known source
        for param_name in param_names:
            if param_name in self.data_flow:
                source_types = self.data_flow[param_name]
                # Find the source details
                for source in self.sources:
                    if source.get("variable") == param_name or source.get("type") in source_types:
                        return {
                            "type": source.get("type", "unknown"),
                            "line": source.get("line"),
                            "variable": param_name,
                        }
        
        # Check if function body uses variables that come from sources
        used_vars = self._extract_variable_usage(func_body)
        for var_name in used_vars:
            if var_name in self.data_flow:
                source_types = self.data_flow[var_name]
                for source in self.sources:
                    if source.get("variable") == var_name or source.get("type") in source_types:
                        return {
                            "type": source.get("type", "unknown"),
                            "line": source.get("line"),
                            "variable": var_name,
                        }
        
        return None
    
    def _extract_variable_usage(self, node: Any) -> List[str]:
        """
        Extract variable names used in a node.
        
        Args:
            node: AST node to analyze
            
        Returns:
            List of variable names used
        """
        used_vars = []
        
        if not isinstance(node, dict):
            return used_vars
        
        node_type = node.get("type")
        
        if node_type == "Identifier":
            used_vars.append(node.get("name"))
        elif node_type == "MemberExpression":
            # Extract object name
            obj = node.get("object", {})
            if obj.get("type") == "Identifier":
                used_vars.append(obj.get("name"))
        
        # Recursively search children
        for key, value in node.items():
            if key in ("loc", "range", "leadingComments", "trailingComments"):
                continue
            if isinstance(value, dict):
                used_vars.extend(self._extract_variable_usage(value))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        used_vars.extend(self._extract_variable_usage(item))
        
        return list(set(used_vars))  # Remove duplicates
    
    def _find_prototype_pollution_sinks(self, node: Any, func_name: str) -> Dict[str, Any]:
        """
        Find prototype pollution sinks in AST nodes using semantic analysis.
        
        Sinks are dangerous operations where user-controlled data flows:
        - Property assignments: obj[key] = value
        - Object.assign calls
        
        Args:
            node: AST node to analyze
            func_name: Function name (for detecting recursive calls)
            
        Returns:
            Dictionary with sink analysis results
        """
        result = {
            "has_sink": False,
            "has_validation": False,
            "has_partial_validation": False,
            "is_recursive": False,
        }
        
        if not isinstance(node, dict):
            return result
        
        node_type = node.get("type")
        
        # Check for property assignment sinks
        if node_type == "AssignmentExpression":
            left = node.get("left", {})
            if left.get("type") == "MemberExpression":
                # Check if this is a property assignment: obj[key] = value
                # This is a sink if:
                # 1. The property is accessed via computed property (obj[key])
                # 2. Or it's a direct dangerous property assignment
                computed = left.get("computed", False)
                prop_name = self._get_property_name_from_ast(left)
                
                if computed:
                    # obj[key] = value - this is a sink (key comes from variable)
                    result["has_sink"] = True
                elif prop_name and prop_name in self.DANGEROUS_PROPERTIES:
                    # Direct dangerous property assignment
                    result["has_sink"] = True
        
        # Check for Object.assign sinks
        elif node_type == "CallExpression":
            callee = node.get("callee", {})
            callee_name = self._get_function_name_from_ast(callee)
            
            if callee_name == "Object.assign":
                result["has_sink"] = True
            
            # Check for recursive function calls
            if callee_name == func_name:
                result["is_recursive"] = True
        
        # Check for for...in loops (common in merge functions)
        elif node_type == "ForInStatement":
            # For...in loops are sinks when combined with property assignments
            result["has_sink"] = True
        
        # Check for validation patterns in AST
        validation_check = self._check_validation_in_ast(node)
        if validation_check["has_full_validation"]:
            result["has_validation"] = True
        elif validation_check["has_partial_validation"]:
            result["has_partial_validation"] = True
        
        # Recursively analyze children
        for key, value in node.items():
            if key in ("loc", "range", "leadingComments", "trailingComments"):
                continue
            if isinstance(value, dict):
                child_result = self._find_prototype_pollution_sinks(value, func_name)
                result["has_sink"] = result["has_sink"] or child_result["has_sink"]
                result["has_validation"] = result["has_validation"] or child_result["has_validation"]
                result["has_partial_validation"] = result["has_partial_validation"] or child_result["has_partial_validation"]
                result["is_recursive"] = result["is_recursive"] or child_result["is_recursive"]
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        child_result = self._find_prototype_pollution_sinks(item, func_name)
                        result["has_sink"] = result["has_sink"] or child_result["has_sink"]
                        result["has_validation"] = result["has_validation"] or child_result["has_validation"]
                        result["has_partial_validation"] = result["has_partial_validation"] or child_result["has_partial_validation"]
                        result["is_recursive"] = result["is_recursive"] or child_result["is_recursive"]
        
        return result
    
    def _get_property_name_from_ast(self, member_expr: Dict[str, Any]) -> Optional[str]:
        """
        Extract property name from a MemberExpression AST node.
        
        Args:
            member_expr: MemberExpression AST node
            
        Returns:
            Property name or None
        """
        if member_expr.get("type") != "MemberExpression":
            return None
        
        prop = member_expr.get("property", {})
        if prop.get("type") == "Identifier":
            return prop.get("name")
        elif prop.get("type") == "Literal":
            return str(prop.get("value"))
        
        return None
    
    def _get_function_name_from_ast(self, callee: Dict[str, Any]) -> Optional[str]:
        """
        Extract function name from a CallExpression callee AST node.
        
        Args:
            callee: Callee AST node
            
        Returns:
            Function name or None
        """
        if callee.get("type") == "Identifier":
            return callee.get("name")
        elif callee.get("type") == "MemberExpression":
            obj = callee.get("object", {})
            prop = callee.get("property", {})
            if obj.get("type") == "Identifier" and prop.get("type") == "Identifier":
                return f"{obj.get('name')}.{prop.get('name')}"
        
        return None
    
    def _check_validation_in_ast(self, node: Any) -> Dict[str, bool]:
        """
        Check if AST node contains validation for dangerous properties.
        
        Args:
            node: AST node to check
            
        Returns:
            Dictionary with validation check results
        """
        result = {
            "has_full_validation": False,
            "has_partial_validation": False,
        }
        
        if not isinstance(node, dict):
            return result
        
        node_type = node.get("type")
        
        # Check for binary expressions comparing to dangerous properties
        if node_type == "BinaryExpression":
            operator = node.get("operator")
            if operator in ("===", "!==", "==", "!="):
                left = node.get("left", {})
                right = node.get("right", {})
                
                # Check if comparing to dangerous property string
                left_val = self._get_string_value_from_ast(left)
                right_val = self._get_string_value_from_ast(right)
                
                dangerous_found = []
                for prop in self.DANGEROUS_PROPERTIES:
                    if prop in (left_val, right_val):
                        dangerous_found.append(prop)
                
                if len(dangerous_found) == len(self.DANGEROUS_PROPERTIES):
                    result["has_full_validation"] = True
                elif len(dangerous_found) > 0:
                    result["has_partial_validation"] = True
        
        # Check for CallExpression to hasOwnProperty
        elif node_type == "CallExpression":
            callee = node.get("callee", {})
            callee_name = self._get_function_name_from_ast(callee)
            if "hasOwnProperty" in (callee_name or ""):
                result["has_full_validation"] = True
        
        # Recursively check children
        for key, value in node.items():
            if key in ("loc", "range", "leadingComments", "trailingComments"):
                continue
            if isinstance(value, dict):
                child_result = self._check_validation_in_ast(value)
                result["has_full_validation"] = result["has_full_validation"] or child_result["has_full_validation"]
                result["has_partial_validation"] = result["has_partial_validation"] or child_result["has_partial_validation"]
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        child_result = self._check_validation_in_ast(item)
                        result["has_full_validation"] = result["has_full_validation"] or child_result["has_full_validation"]
                        result["has_partial_validation"] = result["has_partial_validation"] or child_result["has_partial_validation"]
        
        return result
    
    def _get_string_value_from_ast(self, node: Dict[str, Any]) -> Optional[str]:
        """
        Extract string value from AST node.
        
        Args:
            node: AST node
            
        Returns:
            String value or None
        """
        if node.get("type") == "Literal":
            return str(node.get("value", ""))
        elif node.get("type") == "Identifier":
            return node.get("name")
        
        return None
    
    
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
