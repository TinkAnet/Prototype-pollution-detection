"""
Analysis module for detecting prototype pollution patterns.

This module contains the core logic for analyzing parsed JavaScript code
and HTML files to identify potential prototype pollution vulnerabilities.
Uses semantic AST analysis instead of regex pattern matching.
"""

from typing import Dict, List, Any, Optional, Set, Tuple
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
    file: str = ""  # File where vulnerability was found


class PrototypePollutionAnalyzer:
    """
    Analyzer for detecting prototype pollution vulnerabilities.
    
    This class implements various heuristics and patterns to identify
    potential prototype pollution issues in JavaScript code and HTML files.
    """
    
    # Common dangerous property names that could lead to pollution
    DANGEROUS_PROPERTIES = frozenset({
        "__proto__",
        "prototype",
        "constructor",
    })
    
    # Extra sink callsites and library merge hints
    SINK_CALLEES = {
        "Object.assign",
        "Object.defineProperty",
        "Object.defineProperties",
        "Object.setPrototypeOf",
        "Reflect.setPrototypeOf",
    }
    
    MERGE_NAME_HINTS = {  # for libs and helpers
        "extend", "merge", "deepmerge", "mergeWith", "assignIn", "defaultsDeep", 
        "mixin", "cloneDeep", "applyToDefaults", "assignDeep"
    }
    
    SAFE_TARGET_CREATORS = {"Object.create"}  # Object.create(null) target is safer
    
    def __init__(self, verbose: bool = False):
        """
        Initialize the analyzer.
        
        Args:
            verbose: Enable verbose output
        """
        self.verbose = verbose
        self.vulnerabilities: List[Vulnerability] = []
        self.sources: List[Dict[str, Any]] = []
        self.tainted_vars: Dict[Tuple[str, str], Dict[str, Any]] = {}  # (file, var_name) -> source_info
        self.function_calls: List[Dict[str, Any]] = []
        self.all_asts: List[Dict[str, Any]] = []
        
        # NEW: Track tainted property-name variables (keys in for-in/Object.keys loops)
        self.tainted_keys: Dict[Tuple[str, str], Dict[str, Any]] = {}  # (file, key_var) -> source_info
        
        # Indexing for performance
        self.parent_map: Dict[int, Dict[str, Any]] = {}
        self.func_index: Dict[str, List[Dict[str, Any]]] = {}
        self.sink_function_names: Set[str] = set()
        self._seen_vulns: Set[Tuple[str, int, int, str]] = set()
    
    def reset(self) -> None:
        """
        Reset analyzer state for a new analysis run.
        
        Call this between analyses to prevent state bleeding across projects.
        Alternatively, create a new analyzer instance per project.
        """
        self.vulnerabilities = []
        self.sources = []
        self.tainted_vars = {}
        self.tainted_keys = {}
        self.function_calls = []
        self.all_asts = []
        self.parent_map = {}
        self.func_index = {}
        self.sink_function_names = set()
        self._seen_vulns = set()
    
    def analyze_ast(self, ast: Dict[str, Any]) -> List[Vulnerability]:
        """
        Analyze an AST for prototype pollution vulnerabilities.
        
        This method collects ASTs for cross-file taint analysis.
        
        Args:
            ast: Parsed AST dictionary (from parser)
            
        Returns:
            List of detected vulnerabilities
        """
        # Store AST for later cross-file analysis
        self.all_asts.append(ast)
        
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
    
    def finalize_analysis(self) -> None:
        """
        Perform cross-file taint analysis after all files are analyzed.
        
        This method:
        1. Builds taint propagation graph across all files
        2. Tracks taint through function calls
        3. Detects source-to-sink flows
        """
        if len(self.all_asts) <= 1:
            return  # No cross-file analysis needed
        
        if self.verbose:
            print("Performing cross-file taint analysis...")
        
        # Step 1: Collect all sources and build taint map
        self._build_global_taint_map()
        
        # Step 2: Propagate taint through assignments and function calls
        self._propagate_taint()
        
        # Step 3: Check sinks for tainted data
        self._check_tainted_sinks()
    
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
        """
        # NEW: Index parent pointers + functions and precompute sinks once
        self._index_ast(ast)
        
        # Step 1: Detect sources (JSON.parse, DOM attributes, user input)
        self._detect_sources(ast)
        
        # Step 2: Track initial taint (variable assignments from sources)
        self._track_initial_taint(ast)
        
        # NEW: Track key taint (loop variables that iterate over tainted objects)
        self._track_key_taint(ast)
        
        # Step 3: Extract function calls for taint propagation
        self._extract_function_calls(ast)
        
        # Step 4: Analyze ALL functions for vulnerabilities (sinks)
        functions = ast.get("functions", [])
        for func in functions:
            self._check_function_vulnerability(func, ast)
        
        # Step 5: Check for direct dangerous property assignments
        assignments = ast.get("assignments", [])
        for assign in assignments:
            prop_name = assign.get("property", "")
            if prop_name in self.DANGEROUS_PROPERTIES:
                self._add_vuln(
                    severity="high",
                    line=assign.get("line", 0) or 0,
                    column=assign.get("column", 0) or 0,
                    message=(
                        f"Direct assignment to dangerous property '{prop_name}'. "
                        f"This could lead to prototype pollution."
                    ),
                    code_snippet=assign.get("code", ""),
                    vulnerability_type="direct_dangerous_property_assignment",
                    file=ast.get("file", ""),
                )
    
    def _index_ast(self, ast: Dict[str, Any]) -> None:
        """
        Index AST once: build parent pointers, function index, and precompute sinks.
        
        Args:
            ast: Parsed AST dictionary
        """
        root = ast.get("ast")
        if not root:
            return
        
        # Build parent pointers once
        self._build_parent_map(root, None)
        
        # Build function index & precompute which functions contain sinks
        funcs = ast.get("functions", [])
        for f in funcs:
            node = f.get("ast_node") or self._traverse_ast_for_function(root, f.get("name", ""), f.get("line", 0))
            if not node:
                continue
            
            name = f.get("name", "")
            if name:
                self.func_index.setdefault(name, []).append({
                    "node": node,
                    "file": ast.get("file", "")
                })
                
                # Precompute sink presence once per function
                func_body = node.get("body", {})
                sinks = self._find_prototype_pollution_sinks(func_body, name)
                if sinks["has_sink"]:
                    self.sink_function_names.add(name)
    
    def _build_parent_map(self, node: Any, parent: Optional[Dict[str, Any]]) -> None:
        """
        Build parent pointer map for efficient parent lookups.
        
        Args:
            node: AST node
            parent: Parent node (None for root)
        """
        if not isinstance(node, dict):
            return
        
        if parent is not None:
            self.parent_map[id(node)] = parent
        
        for k, v in node.items():
            if k in ("loc", "range", "leadingComments", "trailingComments"):
                continue
            if isinstance(v, dict):
                self._build_parent_map(v, node)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        self._build_parent_map(item, node)
    
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
        
        filename = ast.get("file", "unknown")
        self._find_sources_in_ast(ast_root, None, filename)
        
        # Also check json_parse_calls extracted by parser
        for json_call in ast.get("json_parse_calls", []):
            self.sources.append({
                "type": "json_parse",
                "line": json_call.get("line"),
                "column": json_call.get("column"),
                "code": json_call.get("code", ""),
                "variable": None,  # Will be extracted from AST
                "file": filename,
            })
    
    def _find_sources_in_ast(self, node: Any, parent: Optional[Any] = None, filename: str = "unknown") -> None:
        """
        Recursively find source nodes in AST.
        
        Args:
            node: AST node to analyze
            parent: Parent node for context
        """
        if not isinstance(node, dict):
            return
        
        node_type = node.get("type")
        
        # Detect JSON.parse() calls
        if node_type == "CallExpression":
            callee = node.get("callee", {})
            callee_name = self._get_function_name_from_ast(callee)
            
            if callee_name == "JSON.parse":
                variable_name = self._get_assigned_variable(node, parent)
                source_info = {
                    "type": "json_parse",
                    "line": node.get("loc", {}).get("start", {}).get("line"),
                    "column": node.get("loc", {}).get("start", {}).get("column"),
                    "variable": variable_name,
                    "file": filename,
                    "node": node,
                }
                self.sources.append(source_info)
            
            # Detect DOM attribute access patterns
            elif callee_name and ("getAttribute" in callee_name or "dataset" in callee_name):
                variable_name = self._get_assigned_variable(node, parent)
                source_info = {
                    "type": "dom_attribute",
                    "line": node.get("loc", {}).get("start", {}).get("line"),
                    "column": node.get("loc", {}).get("start", {}).get("column"),
                    "variable": variable_name,
                    "method": callee_name,
                    "file": filename,
                    "node": node,
                }
                self.sources.append(source_info)
            
            # Detect querySelector/querySelectorAll (often used with getAttribute)
            elif callee_name and "querySelector" in callee_name:
                variable_name = self._get_assigned_variable(node, parent)
                if variable_name:
                    source_info = {
                        "type": "dom_query",
                        "line": node.get("loc", {}).get("start", {}).get("line"),
                        "column": node.get("loc", {}).get("start", {}).get("column"),
                        "variable": variable_name,
                        "method": callee_name,
                        "file": filename,
                        "node": node,
                    }
                    self.sources.append(source_info)
        
            # Detect form input access
        elif node_type == "MemberExpression":
            prop_name = self._get_property_name_from_ast(node)
            if prop_name in ("value", "textContent", "innerHTML"):
                obj_name = self._get_object_name_from_ast(node)
                if obj_name:
                    variable_name = self._get_assigned_variable(node, parent)
                    source_info = {
                        "type": "user_input",
                        "line": node.get("loc", {}).get("start", {}).get("line"),
                        "column": node.get("loc", {}).get("start", {}).get("column"),
                        "variable": variable_name,
                        "property": prop_name,
                        "object": obj_name,
                        "file": filename,
                        "node": node,
                    }
                    self.sources.append(source_info)
            
            # Detect Node.js/Express sources (req.body, req.query, req.params)
            obj_name = self._get_object_name_from_ast(node)
            if obj_name in ("req", "request") and prop_name in ("body", "query", "params", "headers"):
                variable_name = self._get_assigned_variable(node, parent)
                source_info = {
                    "type": f"express_{prop_name}",
                    "line": node.get("loc", {}).get("start", {}).get("line"),
                    "column": node.get("loc", {}).get("start", {}).get("column"),
                    "variable": variable_name,
                    "property": prop_name,
                    "object": obj_name,
                    "file": filename,
                    "node": node,
                }
                self.sources.append(source_info)
            
            # Detect browser sources (location.search, location.hash)
            if obj_name == "location" and prop_name in ("search", "hash", "href"):
                variable_name = self._get_assigned_variable(node, parent)
                source_info = {
                    "type": "url_param",
                    "line": node.get("loc", {}).get("start", {}).get("line"),
                    "column": node.get("loc", {}).get("start", {}).get("column"),
                    "variable": variable_name,
                    "property": prop_name,
                    "object": obj_name,
                    "file": filename,
                    "node": node,
                }
                self.sources.append(source_info)
        
        # Recursively search children with parent context
        for key, value in node.items():
            if key in ("loc", "range", "leadingComments", "trailingComments"):
                continue
            if isinstance(value, dict):
                self._find_sources_in_ast(value, node, filename)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        self._find_sources_in_ast(item, node, filename)
    
    def _get_assigned_variable(self, node: Any, parent: Optional[Any] = None) -> Optional[str]:
        """
        Climb to the nearest VariableDeclarator or AssignmentExpression using parent map.
        
        Args:
            node: AST node (usually a CallExpression)
            parent: Parent node (if explicitly provided)
            
        Returns:
            Variable name or None
        """
        cur = node
        # If parent explicitly provided, start there; otherwise, use parent_map
        if parent is None:
            parent = self.parent_map.get(id(cur))
        
        while parent:
            ptype = parent.get("type")
            if ptype == "VariableDeclarator":
                var_id = parent.get("id", {})
                if var_id.get("type") == "Identifier":
                    return var_id.get("name")
                return None
            if ptype == "AssignmentExpression":
                left = parent.get("left", {})
                if left.get("type") == "Identifier":
                    return left.get("name")
                return None
            cur = parent
            parent = self.parent_map.get(id(cur))
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
    
    def _track_initial_taint(self, ast: Dict[str, Any]) -> None:
        """
        Track initial taint by analyzing variable assignments from sources.
        
        This marks variables as tainted when they're assigned from sources.
        
        Args:
            ast: Parsed AST dictionary
        """
        ast_root = ast.get("ast")
        if not ast_root:
            return
        
        self._extract_variable_assignments(ast_root, ast.get("file", "unknown"))
    
    def _track_key_taint(self, ast: Dict[str, Any]) -> None:
        """
        Track variables that are used as property keys when iterating over tainted objects.
        
        Examples:
            for (const key in src) { target[key] = src[key]; }
            for (const key of Object.keys(src)) { ... }
        
        Args:
            ast: Parsed AST dictionary
        """
        ast_root = ast.get("ast")
        if not ast_root:
            return
        
        self._find_key_taint(ast_root, ast.get("file", "unknown"))
    
    def _find_key_taint(self, node: Any, filename: str) -> None:
        """
        Recursively find patterns that make a variable a tainted 'key' variable.
        
        Args:
            node: AST node to analyze
            filename: Current filename
        """
        if not isinstance(node, dict):
            return
        
        ntype = node.get("type")
        
        # Pattern 1: for (key in src) { ... }
        if ntype == "ForInStatement":
            left = node.get("left")
            right = node.get("right")
            
            # Right side is the object being iterated
            src_name = None
            if isinstance(right, dict) and right.get("type") == "Identifier":
                src_name = right.get("name")
            
            if src_name and (filename, src_name) in self.tainted_vars:
                # Left side is the loop variable
                key_name = None
                if isinstance(left, dict):
                    if left.get("type") == "VariableDeclaration":
                        decls = left.get("declarations") or []
                        if decls:
                            did = decls[0].get("id", {})
                            if did.get("type") == "Identifier":
                                key_name = did.get("name")
                    elif left.get("type") == "Identifier":
                        key_name = left.get("name")
                
                if key_name:
                    src_taint = self.tainted_vars[(filename, src_name)]
                    self.tainted_keys[(filename, key_name)] = {
                        "source_type": src_taint.get("source_type", "unknown"),
                        "source_line": src_taint.get("source_line"),
                        "source_file": src_taint.get("source_file", filename),
                        "tainted_from": src_name,
                        "tainted_at": "for_in",
                    }
        
        # Pattern 2: for (key of Object.keys(src)) { ... }
        elif ntype == "ForOfStatement":
            left = node.get("left")
            right = node.get("right")
            
            key_name = None
            if isinstance(left, dict):
                if left.get("type") == "VariableDeclaration":
                    decls = left.get("declarations") or []
                    if decls:
                        did = decls[0].get("id", {})
                        if did.get("type") == "Identifier":
                            key_name = did.get("name")
                elif left.get("type") == "Identifier":
                    key_name = left.get("name")
            
            src_name = None
            if isinstance(right, dict) and right.get("type") == "CallExpression":
                callee = right.get("callee", {})
                callee_name = self._get_function_name_from_ast(callee)
                
                if callee_name and (callee_name == "Object.keys" or callee_name.endswith(".keys")):
                    args = right.get("arguments") or []
                    if args and args[0].get("type") == "Identifier":
                        src_name = args[0].get("name")
            
            if key_name and src_name and (filename, src_name) in self.tainted_vars:
                src_taint = self.tainted_vars[(filename, src_name)]
                self.tainted_keys[(filename, key_name)] = {
                    "source_type": src_taint.get("source_type", "unknown"),
                    "source_line": src_taint.get("source_line"),
                    "source_file": src_taint.get("source_file", filename),
                    "tainted_from": src_name,
                    "tainted_at": "for_of_object_keys",
                }
        
        # Recurse
        for k, v in node.items():
            if k in ("loc", "range", "leadingComments", "trailingComments"):
                continue
            if isinstance(v, dict):
                self._find_key_taint(v, filename)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        self._find_key_taint(item, filename)
    
    def _extract_function_calls(self, ast: Dict[str, Any]) -> None:
        """
        Extract function calls for taint propagation analysis.
        
        Args:
            ast: Parsed AST dictionary
        """
        ast_root = ast.get("ast")
        if not ast_root:
            return
        
        self._find_function_calls(ast_root, ast.get("file", "unknown"))
    
    def _find_function_calls(self, node: Any, filename: str, parent: Optional[Any] = None) -> None:
        """
        Recursively find function call expressions.
        
        Args:
            node: AST node
            filename: Current filename
            parent: Parent node for context
        """
        if not isinstance(node, dict):
            return
        
        node_type = node.get("type")
        
        if node_type == "CallExpression":
            callee = node.get("callee", {})
            func_name = self._get_function_name_from_ast(callee)
            args = node.get("arguments", [])
            
            # Extract argument variables and check for direct sources
            arg_info = []
            for arg in args:
                arg_var = None
                is_direct_source = False
                source_type = None
                
                if arg.get("type") == "Identifier":
                    arg_var = arg.get("name")
                elif arg.get("type") == "MemberExpression":
                    obj = arg.get("object", {})
                    if obj.get("type") == "Identifier":
                        arg_var = obj.get("name")
                elif arg.get("type") == "CallExpression":
                    # Check if argument is a direct source call (e.g., extend({}, JSON.parse(...)))
                    arg_callee = arg.get("callee", {})
                    arg_callee_name = self._get_function_name_from_ast(arg_callee)
                    if arg_callee_name == "JSON.parse":
                        is_direct_source = True
                        source_type = "json_parse"
                    elif arg_callee_name and ("getAttribute" in arg_callee_name or "dataset" in arg_callee_name):
                        is_direct_source = True
                        source_type = "dom_attribute"
                
                arg_info.append({
                    "variable": arg_var,
                    "is_direct_source": is_direct_source,
                    "source_type": source_type,
                    "arg_node": arg,
                })
            
            # Find what variable this call is assigned to
            assigned_var = None
            if parent and parent.get("type") == "VariableDeclarator":
                var_id = parent.get("id", {})
                if var_id.get("type") == "Identifier":
                    assigned_var = var_id.get("name")
            elif parent and parent.get("type") == "AssignmentExpression":
                left = parent.get("left", {})
                if left.get("type") == "Identifier":
                    assigned_var = left.get("name")
            
            self.function_calls.append({
                "function": func_name,
                "arguments": arg_info,
                "assigned_to": assigned_var,
                "line": node.get("loc", {}).get("start", {}).get("line"),
                "file": filename,
                "node": node,
            })
        
        # Recursively search children
        for key, value in node.items():
            if key in ("loc", "range", "leadingComments", "trailingComments"):
                continue
            if isinstance(value, dict):
                self._find_function_calls(value, filename, node)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        self._find_function_calls(item, filename, node)
    
    def _extract_variable_assignments(self, node: Any, filename: str) -> None:
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
                        # Mark variable as tainted
                        self.tainted_vars[(filename, var_name)] = {
                            "source_type": "json_parse",
                            "source_line": init.get("loc", {}).get("start", {}).get("line"),
                            "source_file": filename,
                            "tainted_at": "variable_declaration",
                        }
                        self._update_source_variable(init, var_name)
                    
                    elif callee_name and ("getAttribute" in callee_name or "dataset" in callee_name):
                        self.tainted_vars[(filename, var_name)] = {
                            "source_type": "dom_attribute",
                            "source_line": init.get("loc", {}).get("start", {}).get("line"),
                            "source_file": filename,
                            "tainted_at": "variable_declaration",
                        }
                        self._update_source_variable(init, var_name)
                    
                    elif callee_name and "querySelector" in callee_name:
                        self.tainted_vars[(filename, var_name)] = {
                            "source_type": "dom_query",
                            "source_line": init.get("loc", {}).get("start", {}).get("line"),
                            "source_file": filename,
                            "tainted_at": "variable_declaration",
                        }
                        self._update_source_variable(init, var_name)
                
                # Check for nested patterns like: var x = element.getAttribute('data')
                elif init.get("type") == "MemberExpression":
                    # This handles cases like: var x = el.getAttribute('data')
                    obj = init.get("object", {})
                    prop = init.get("property", {})
                    if prop.get("type") == "Identifier" and prop.get("name") in ("getAttribute", "dataset"):
                        self.tainted_vars[(filename, var_name)] = {
                            "source_type": "dom_attribute",
                            "source_line": init.get("loc", {}).get("start", {}).get("line"),
                            "source_file": filename,
                            "tainted_at": "variable_declaration",
                        }
                
                # Check if init is a tainted variable (taint propagation)
                elif init.get("type") == "Identifier":
                    init_var = init.get("name")
                    if (filename, init_var) in self.tainted_vars:
                        # Propagate taint
                        self.tainted_vars[(filename, var_name)] = self.tainted_vars[(filename, init_var)].copy()
                        self.tainted_vars[(filename, var_name)]["tainted_at"] = "assignment"
                        self.tainted_vars[(filename, var_name)]["propagated_from"] = init_var
                    
                    # NEW: Key-taint propagation for variable declarations
                    if (filename, init_var) in self.tainted_keys:
                        key_taint = self.tainted_keys[(filename, init_var)].copy()
                        key_taint["tainted_at"] = "assignment"
                        key_taint["propagated_from"] = init_var
                        self.tainted_keys[(filename, var_name)] = key_taint
        
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
                        self.tainted_vars[(filename, var_name)] = {
                            "source_type": "json_parse",
                            "source_line": right.get("loc", {}).get("start", {}).get("line"),
                            "source_file": filename,
                            "tainted_at": "assignment",
                        }
                        self._update_source_variable(right, var_name)
                    
                    elif callee_name and ("getAttribute" in callee_name or "dataset" in callee_name):
                        self.tainted_vars[(filename, var_name)] = {
                            "source_type": "dom_attribute",
                            "source_line": right.get("loc", {}).get("start", {}).get("line"),
                            "source_file": filename,
                            "tainted_at": "assignment",
                        }
                        self._update_source_variable(right, var_name)
                
                # Check if right side is a tainted variable (taint propagation)
                elif right.get("type") == "Identifier":
                    right_var = right.get("name")
                    if (filename, right_var) in self.tainted_vars:
                        # Propagate taint
                        self.tainted_vars[(filename, var_name)] = self.tainted_vars[(filename, right_var)].copy()
                        self.tainted_vars[(filename, var_name)]["tainted_at"] = "assignment"
                        self.tainted_vars[(filename, var_name)]["propagated_from"] = right_var
                    
                    # NEW: Key-taint propagation for assignments
                    if (filename, right_var) in self.tainted_keys:
                        key_taint = self.tainted_keys[(filename, right_var)].copy()
                        key_taint["tainted_at"] = "assignment"
                        key_taint["propagated_from"] = right_var
                        self.tainted_keys[(filename, var_name)] = key_taint
        
        # Recursively search children
        for key, value in node.items():
            if key in ("loc", "range", "leadingComments", "trailingComments"):
                continue
            if isinstance(value, dict):
                self._extract_variable_assignments(value, filename)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        self._extract_variable_assignments(item, filename)
    
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
            has_key_taint = analysis_result.get("has_key_taint", False)  # Should be passed from _analyze_function_ast if implemented fully there
            
            # Check if we have message already constructed in analysis_result
            if analysis_result.get("message"):
                message = analysis_result.get("message")
            elif source_info:
                message = (
                    f"Function '{func_display_name}' performs property copying/merging "
                    f"with data from {source_info['type']} source (line {source_info['line']}) "
                    f"without validating dangerous properties. This creates a prototype pollution vulnerability."
                )
            else:
                message = f"Function '{func_display_name}' is vulnerable to prototype pollution."
            
            code_snippet = func.get("body", "")[:300] if func.get("body") else ""
            
            self._add_vuln(
                severity=severity,
                line=func_line,
                column=func_column,
                message=message,
                code_snippet=code_snippet,
                vulnerability_type=analysis_result.get("vulnerability_type", "vulnerable_function"),
                file=ast.get("file", ""),
            )
    
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
        
        # Support arrow functions too
        if node_type in ("FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"):
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
            "has_key_taint": False,  # NEW: Pass this up
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
            has_key_taint = sink_analysis.get("has_key_taint", False)
            result["has_key_taint"] = has_key_taint  # Store in result
            
            # Check if source data flows to this function
            source_info = self._check_source_to_sink_flow(func_body, param_names, ast)
            
            if not has_validation:
                result["is_vulnerable"] = True
                
                # NEW: Bump severity when key names are tainted or when we have source->sink info
                if has_key_taint or source_info:
                    result["severity"] = "high"
                else:
                    result["severity"] = "medium"
                
                if is_recursive:
                    result["vulnerability_type"] = "vulnerable_recursive_merge"
                else:
                    result["vulnerability_type"] = "vulnerable_property_assignment"
                
                result["source_info"] = source_info
                
                if source_info:
                    result["vulnerability_type"] = "source_to_sink_pollution"
                    result["message"] = (
                        f"Function '{func_name if func_name else '(anonymous)'}' receives data from "
                        f"{source_info['type']} source and performs property copying/merging "
                        f"without validating dangerous properties. This creates a prototype pollution vulnerability."
                    )
                elif has_key_taint:  # NEW
                    result["message"] = (
                        f"Function '{func_name if func_name else '(anonymous)'}' copies properties using a key "
                        f"variable that comes from a tainted object (e.g., for-in over user-controlled data) "
                        f"without validating dangerous properties (__proto__, constructor, prototype). "
                        f"This is a strong prototype pollution candidate."
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
    
    def _build_global_taint_map(self) -> None:
        """
        Build global taint map across all files.
        
        This collects all sources and initial taint assignments.
        """
        # Sources are already collected during _detect_sources calls
        # Tainted vars are already collected during _track_initial_taint
        if self.verbose:
            print(f"  Found {len(self.sources)} sources")
            print(f"  Found {len(self.tainted_vars)} tainted variables")
            
            # Print sources
            if self.sources:
                print("\n  Sources detected:")
                for i, source in enumerate(self.sources, 1):
                    var_info = f" -> variable '{source.get('variable')}'" if source.get('variable') else ""
                    print(f"    {i}. {source.get('type', 'unknown')} at line {source.get('line', '?')} in {source.get('file', 'unknown')}{var_info}")
            
            # Print tainted variables
            if self.tainted_vars:
                print("\n  Tainted variables:")
                for (file_name, var_name), taint_info in self.tainted_vars.items():
                    source_type = taint_info.get('source_type', 'unknown')
                    source_line = taint_info.get('source_line', '?')
                    source_file = taint_info.get('source_file', 'unknown')
                    tainted_at = taint_info.get('tainted_at', 'unknown')
                    propagated_from = taint_info.get('propagated_from')
                    prop_info = f" (propagated from '{propagated_from}')" if propagated_from else ""
                    print(f"    - '{var_name}' in {file_name}: {source_type} source at line {source_line} in {source_file} ({tainted_at}){prop_info}")
            
            # Print tainted keys (property name variables)
            if self.tainted_keys:
                print("\n  Tainted keys (property names from tainted objects):")
                for (file_name, key_name), taint_info in self.tainted_keys.items():
                    source_type = taint_info.get('source_type', 'unknown')
                    source_line = taint_info.get('source_line', '?')
                    source_file = taint_info.get('source_file', 'unknown')
                    tainted_at = taint_info.get('tainted_at', 'unknown')
                    tainted_from = taint_info.get('tainted_from', 'unknown')
                    propagated_from = taint_info.get('propagated_from')
                    prop_info = f" (propagated from '{propagated_from}')" if propagated_from else f" (from '{tainted_from}')"
                    print(f"    - '{key_name}' in {file_name}: {source_type} source at line {source_line} in {source_file} ({tainted_at}){prop_info}")
            
            # Print function calls with tainted arguments
            tainted_calls = [c for c in self.function_calls if c.get('tainted')]
            if tainted_calls:
                print("\n  Tainted function calls:")
                for call in tainted_calls:
                    func_name = call.get('function', 'unknown')
                    call_line = call.get('line', '?')
                    call_file = call.get('file', 'unknown')
                    tainted_args = call.get('tainted_args', [])
                    arg_info = []
                    for arg in tainted_args:
                        if arg.get('is_direct_source'):
                            arg_info.append(f"direct {arg.get('source_type')} source")
                        else:
                            var = arg.get('variable')
                            if var:
                                arg_info.append(f"'{var}'")
                    args_str = ", ".join(arg_info) if arg_info else "unknown"
                    print(f"    - {func_name}() at line {call_line} in {call_file} receives: {args_str}")
    
    def _propagate_taint(self) -> None:
        """
        Propagate taint through assignments and function calls.
        
        This implements taint analysis by tracking how tainted data flows
        through variable assignments and function parameters.
        """
        # Propagate taint through assignments (already done in _extract_variable_assignments)
        # Now propagate through function calls
        
        for call in self.function_calls:
            func_name = call.get("function")
            args = call.get("arguments", [])
            
            # Check if any argument is tainted or is a direct source
            tainted_args = []
            for arg_info in args:
                arg_var = arg_info.get("variable")
                is_direct_source = arg_info.get("is_direct_source", False)
                source_type = arg_info.get("source_type")
                
                if is_direct_source:
                    # Direct source in function call (e.g., extend({}, JSON.parse(...)))
                    tainted_args.append({
                        "variable": None,
                        "is_direct_source": True,
                        "source_type": source_type,
                        "taint_info": {
                            "source_type": source_type,
                            "source_line": call.get("line"),
                            "source_file": call.get("file"),
                        }
                    })
                elif arg_var and (call.get("file", ""), arg_var) in self.tainted_vars:
                    # Tainted variable passed as argument
                    tainted_args.append({
                        "variable": arg_var,
                        "is_direct_source": False,
                        "taint_info": self.tainted_vars[(call.get("file", ""), arg_var)]
                    })
            
            # If function is a sink and receives tainted data, mark it
            if tainted_args and self._is_sink_function(func_name):
                call["tainted"] = True
                call["tainted_args"] = tainted_args
    
    def _is_sink_function(self, func_name: Optional[str]) -> bool:
        """
        Check if a function is a known sink (vulnerable merge/extend function).
        
        O(1) lookup using precomputed sink_function_names set.
        
        Args:
            func_name: Function name
            
        Returns:
            True if function is a sink
        """
        if not func_name:
            return False
        
        # O(1) lookup in precomputed set
        if func_name in self.sink_function_names:
            return True
        
        # Library helpers (e.g., $.extend, _.merge, deepmerge)
        last = func_name.split(".")[-1]
        return last in self.MERGE_NAME_HINTS
    
    def _check_tainted_sinks(self) -> None:
        """
        Check sinks for tainted data and create source-to-sink vulnerabilities.
        
        Creates new vulnerabilities for tainted sink calls even if no existing
        function-level vulnerability exists (e.g., top-level code).
        """
        # Check function calls that are sinks and receive tainted data
        for call in self.function_calls:
            if call.get("tainted"):
                tainted_args = call.get("tainted_args", [])
                if tainted_args:
                    func_name = call.get("function")
                    call_line = call.get("line")
                    call_file = call.get("file")
                    
                    # Find corresponding vulnerability for this sink function
                    matched = False
                    for vuln in self.vulnerabilities:
                        # Match by function name in message or by checking if it's the sink function
                        if func_name and (func_name.lower() in vuln.message.lower() or 
                                         self._vulnerability_matches_function(vuln, func_name)):
                            # Enhance vulnerability with source information
                            taint_arg = tainted_args[0]
                            taint_info = taint_arg["taint_info"]
                            
                            if taint_arg.get("is_direct_source"):
                                # Direct source in function call
                                source_info = {
                                    "type": taint_info.get("source_type", "unknown"),
                                    "line": call_line,
                                    "file": call_file,
                                    "variable": None,
                                    "direct": True,
                                }
                                vuln.message = (
                                    f"Function '{func_name}' receives tainted data directly from {source_info['type']} source "
                                    f"at line {call_line} in {call_file} and performs property copying/merging "
                                    f"without validating dangerous properties. This creates a prototype pollution vulnerability."
                                )
                            else:
                                # Tainted variable passed as argument
                                source_info = {
                                    "type": taint_info.get("source_type", "unknown"),
                                    "line": taint_info.get("source_line"),
                                    "file": taint_info.get("source_file"),
                                    "variable": taint_arg.get("variable"),
                                    "direct": False,
                                }
                                var_info = f"via variable '{source_info['variable']}'" if source_info["variable"] else ""
                                vuln.message = (
                                    f"Function '{func_name}' receives tainted data from {source_info['type']} source "
                                    f"(line {source_info['line']} in {source_info['file']}) {var_info} "
                                    f"and performs property copying/merging without validating dangerous properties. "
                                    f"This creates a prototype pollution vulnerability. "
                                    f"Tainted data flows from source to sink at line {call_line} in {call_file}."
                                )
                            
                            vuln.vulnerability_type = "source_to_sink_pollution"
                            matched = True
                            break
                    
                    # If no matching vulnerability found, create a new one for this tainted sink call
                    if not matched:
                        taint_arg = tainted_args[0]
                        taint_info = taint_arg["taint_info"]
                        
                        if taint_arg.get("is_direct_source"):
                            message = (
                                f"Call to '{func_name}' at line {call_line} receives tainted data "
                                f"directly from {taint_info.get('source_type', 'unknown')} source. "
                                f"This may cause prototype pollution."
                            )
                        else:
                            var_info = f"via variable '{taint_arg.get('variable')}'" if taint_arg.get("variable") else ""
                            message = (
                                f"Call to '{func_name}' at line {call_line} receives tainted data "
                                f"from {taint_info.get('source_type', 'unknown')} source "
                                f"(line {taint_info.get('source_line')} in {taint_info.get('source_file')}) {var_info}. "
                                f"This may cause prototype pollution."
                            )
                        
                        self._add_vuln(
                            severity="high",
                            line=call_line or 0,
                            column=0,
                            message=message,
                            code_snippet="",
                            vulnerability_type="source_to_sink_pollution",
                            file=call_file or "",
                        )
    
    def _vulnerability_matches_function(self, vuln: Vulnerability, func_name: str) -> bool:
        """
        Check if vulnerability is for a specific function.
        
        Args:
            vuln: Vulnerability object
            func_name: Function name to match
            
        Returns:
            True if vulnerability matches function
        """
        # Extract function name from vulnerability message
        if func_name.lower() in vuln.message.lower():
            return True
        
        # Check code snippet
        if func_name.lower() in vuln.code_snippet.lower():
            return True
        
        return False
    
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
        filename = ast.get("file", "")
        
        # Check if any parameter is tainted
        for param_name in param_names:
            if (filename, param_name) in self.tainted_vars:
                taint_info = self.tainted_vars[(filename, param_name)]
                return {
                    "type": taint_info.get("source_type", "unknown"),
                    "line": taint_info.get("source_line"),
                    "file": taint_info.get("source_file"),
                    "variable": param_name,
                }
        
        # Check if function body uses tainted variables
        used_vars = self._extract_variable_usage(func_body)
        for var_name in used_vars:
            if (filename, var_name) in self.tainted_vars:
                taint_info = self.tainted_vars[(filename, var_name)]
                return {
                    "type": taint_info.get("source_type", "unknown"),
                    "line": taint_info.get("source_line"),
                    "file": taint_info.get("source_file"),
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
    
    def _add_vuln(self, *, severity: str, line: int, column: int, message: str,
                  code_snippet: str, vulnerability_type: str, file: str) -> None:
        """
        Add vulnerability with deduplication.
        
        Args:
            severity: Vulnerability severity
            line: Line number
            column: Column number
            message: Vulnerability message
            code_snippet: Code snippet
            vulnerability_type: Type of vulnerability
            file: File path
        """
        key = (file or "", int(line or 0), int(column or 0), vulnerability_type or "")
        if key in self._seen_vulns:
            return
        self._seen_vulns.add(key)
        self.vulnerabilities.append(Vulnerability(
            severity=severity,
            line=line,
            column=column,
            message=message,
            code_snippet=code_snippet,
            vulnerability_type=vulnerability_type,
            file=file
        ))
    
    def _find_prototype_pollution_sinks(self, node: Any, func_name: str) -> Dict[str, Any]:
        """
        Find prototype pollution sinks in AST nodes using semantic analysis.
        
        Better sink/guard analysis: only marks actual writes as sinks, recognizes guards.
        
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
            # NEW: Track if key variable is tainted
            "has_key_taint": False,
        }
        
        if not isinstance(node, dict):
            return result
        
        ntype = node.get("type")
        
        # 1) Property write: target[key] = value
        if ntype == "AssignmentExpression":
            left = node.get("left", {})
            if left.get("type") == "MemberExpression":
                computed = left.get("computed", False)
                
                # Direct dangerous prop write: target.__proto__ = ...
                if not computed:
                    pname = self._get_property_name_from_ast(left)
                    if pname and pname in self.DANGEROUS_PROPERTIES:
                        result["has_sink"] = True
                        guards = self._is_guarded(node, key_name=None)  # direct name, no key var
                        result["has_validation"] = guards["full"]
                        result["has_partial_validation"] = guards["partial"]
                else:
                    # target[key] = ...
                    # Try to get the key identifier for guard correlation
                    key_node = left.get("property", {})
                    key_name = key_node.get("name") if key_node.get("type") == "Identifier" else None
                    result["has_sink"] = True
                    guards = self._is_guarded(node, key_name=key_name)
                    result["has_validation"] = guards["full"]
                    result["has_partial_validation"] = guards["partial"]
                    
                    # NEW: If the key variable itself is tainted, mark key taint
                    if key_name and key_name in self.tainted_keys:
                        result["has_key_taint"] = True
        
        # 2) Call-based sinks
        elif ntype == "CallExpression":
            callee = node.get("callee", {})
            callee_name = self._get_function_name_from_ast(callee)
            
            if callee_name in self.SINK_CALLEES:
                result["has_sink"] = True
                
                # Lower severity if assigning into fresh null-proto target: Object.assign(Object.create(null), src)
                if callee_name == "Object.assign":
                    args = node.get("arguments", [])
                    if args and args[0].get("type") == "CallExpression":
                        c2 = args[0].get("callee", {})
                        if self._get_function_name_from_ast(c2) in self.SAFE_TARGET_CREATORS:
                            # Treated as validated because prototype is null
                            result["has_validation"] = True
            
            # Recursive call to same function (deep merge)
            if callee_name == func_name:
                result["is_recursive"] = True
            
            # Library helpers (extend/merge-like): treat as sink
            if not result["has_sink"] and callee_name:
                last = callee_name.split(".")[-1]
                if last in self.MERGE_NAME_HINTS:
                    result["has_sink"] = True
        
        # Note: We do NOT treat ForInStatement as a sink by itself; the write inside is the sink.
        
        # Recurse and aggregate
        for key, value in node.items():
            if key in ("loc", "range", "leadingComments", "trailingComments"):
                continue
            if isinstance(value, dict):
                child = self._find_prototype_pollution_sinks(value, func_name)
                result["has_sink"] |= child["has_sink"]
                result["has_validation"] |= child["has_validation"]
                result["has_partial_validation"] |= child["has_partial_validation"]
                result["is_recursive"] |= child["is_recursive"]
                # NEW: Propagate key taint
                result["has_key_taint"] |= child.get("has_key_taint", False)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        child = self._find_prototype_pollution_sinks(item, func_name)
                        result["has_sink"] |= child["has_sink"]
                        result["has_validation"] |= child["has_validation"]
                        result["has_partial_validation"] |= child["has_partial_validation"]
                        result["is_recursive"] |= child["is_recursive"]
                        # NEW: Propagate key taint
                        result["has_key_taint"] |= child.get("has_key_taint", False)
        
        return result
    
    def _is_guarded(self, sink_node: Dict[str, Any], key_name: Optional[str]) -> Dict[str, bool]:
        """
        Walk ancestors and determine whether the sink is dominated by:
        - A full exclusion check: key !== "__proto__" && key !== "constructor" && key !== "prototype"
        - Or an own-property check: foo.hasOwnProperty(key) OR Object.prototype.hasOwnProperty.call(foo, key) (counts as partial)
        
        Returns {"full": bool, "partial": bool}
        
        Args:
            sink_node: Sink node (AssignmentExpression)
            key_name: Name of the key variable (if known)
            
        Returns:
            Dictionary with guard information
        """
        full = False
        partial = False
        cur = sink_node
        seen = set()
        
        while cur and id(cur) not in seen:
            seen.add(id(cur))
            parent = self.parent_map.get(id(cur))
            if not parent:
                break
            
            ptype = parent.get("type")
            
            if ptype == "IfStatement":
                test = parent.get("test", {})
                excl = self._collect_dangerous_exclusions(test, key_name)
                if excl == self.DANGEROUS_PROPERTIES:
                    full = True
                elif excl:
                    partial = True
                
                if self._if_test_has_hasOwnProperty(test, key_name):
                    # hasOwnProperty prevents prototype chain keys but doesn't exclude
                    # dangerous own properties like "__proto__", so treat as partial
                    partial = True
            
            cur = parent
        
        return {"full": full, "partial": partial}
    
    def _collect_dangerous_exclusions(self, test_node: Dict[str, Any], key_name: Optional[str]) -> Set[str]:
        """
        Return the subset of dangerous props excluded by a test of the form:
        key !== "__proto__" && key !== "constructor" && key !== "prototype"
        or the negated form inside an if-branch that skips/continues.
        
        Args:
            test_node: Test expression node
            key_name: Name of the key variable (if known)
            
        Returns:
            Set of dangerous properties that are excluded
        """
        found: Set[str] = set()
        if not isinstance(test_node, dict):
            return found
        
        ntype = test_node.get("type")
        if ntype == "BinaryExpression":
            op = test_node.get("operator")
            left = test_node.get("left", {})
            right = test_node.get("right", {})
            
            # Normalize (Identifier === Literal) or (Literal === Identifier)
            ident = left if left.get("type") == "Identifier" else (right if right.get("type") == "Identifier" else None)
            lit = right if right.get("type") == "Literal" else (left if left.get("type") == "Literal" else None)
            
            if ident and lit:
                if key_name is None or ident.get("name") == key_name:
                    val = str(lit.get("value"))
                    if val in self.DANGEROUS_PROPERTIES:
                        # For !== or != we consider it exclusion (safe path)
                        if op in ("!==", "!="):
                            found.add(val)
        elif ntype == "LogicalExpression":
            # Collect across AND/OR
            found |= self._collect_dangerous_exclusions(test_node.get("left", {}), key_name)
            found |= self._collect_dangerous_exclusions(test_node.get("right", {}), key_name)
        
        return found
    
    def _if_test_has_hasOwnProperty(self, test_node: Dict[str, Any], key_name: Optional[str]) -> bool:
        """
        Detect hasOwnProperty guards in an if() test.
        
        Args:
            test_node: Test expression node
            key_name: Name of the key variable (if known)
            
        Returns:
            True if hasOwnProperty guard is detected
        """
        if not isinstance(test_node, dict):
            return False
        
        ntype = test_node.get("type")
        if ntype == "CallExpression":
            callee = test_node.get("callee", {})
            args = test_node.get("arguments", [])
            name = self._get_function_name_from_ast(callee)
            
            # obj.hasOwnProperty(key)
            if name and name.endswith(".hasOwnProperty") and args:
                return (key_name is None) or (args[0].get("type") == "Identifier" and args[0].get("name") == key_name)
            
            # Object.prototype.hasOwnProperty.call(obj, key)
            if name == "Object.prototype.hasOwnProperty.call" and len(args) >= 2:
                return (key_name is None) or (args[1].get("type") == "Identifier" and args[1].get("name") == key_name)
        elif ntype in ("LogicalExpression", "BinaryExpression"):
            return (self._if_test_has_hasOwnProperty(test_node.get("left", {}), key_name) or
                    self._if_test_has_hasOwnProperty(test_node.get("right", {}), key_name))
        elif ntype == "UnaryExpression":
            return self._if_test_has_hasOwnProperty(test_node.get("argument", {}), key_name)
        elif ntype == "ConditionalExpression":
            return (self._if_test_has_hasOwnProperty(test_node.get("test", {}), key_name) or
                    self._if_test_has_hasOwnProperty(test_node.get("consequent", {}), key_name) or
                    self._if_test_has_hasOwnProperty(test_node.get("alternate", {}), key_name))
        
        return False
    
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
