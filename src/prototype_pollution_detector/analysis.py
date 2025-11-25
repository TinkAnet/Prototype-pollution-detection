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
    
    This class holds all the information about a vulnerability found during
    analysis, including its location, severity, and details about how it
    was detected.
    """
    severity: str  # Severity level: 'high', 'medium', or 'low'
    line: int  # Line number where the vulnerability was found
    column: int  # Column number where the vulnerability was found
    message: str  # Human-readable description of the vulnerability
    code_snippet: str  # The actual code that contains the vulnerability
    vulnerability_type: str  # Type of vulnerability (e.g., 'source_to_sink_pollution')
    file: str = ""  # Path to the file where this vulnerability was found


class PrototypePollutionAnalyzer:
    """
    Analyzer for detecting prototype pollution vulnerabilities in JavaScript code.
    
    This class implements semantic analysis techniques to identify potential
    prototype pollution issues. It tracks data flow from untrusted sources
    (like user input) to dangerous operations (like property copying functions)
    that could lead to prototype pollution attacks.
    """
    
    # These are the dangerous property names that attackers can use to pollute
    # the prototype chain. If any of these are assigned without validation,
    # it can lead to prototype pollution.
    DANGEROUS_PROPERTIES = frozenset({
        "__proto__",
        "prototype",
        "constructor",
    })
    
    # These are built-in JavaScript functions that can be used as sinks.
    # When these functions operate on untrusted data, they can cause
    # prototype pollution if the data contains dangerous properties.
    SINK_CALLEES = {
        "Object.assign",
        "Object.defineProperty",
        "Object.defineProperties",
        "Object.setPrototypeOf",
        "Reflect.setPrototypeOf",
    }
    
    # Common function name patterns that indicate merge/extend operations.
    # These are often found in libraries like jQuery, Lodash, etc.
    # Functions with these names are likely to perform property copying.
    MERGE_NAME_HINTS = {
        "extend", "merge", "deepmerge", "mergeWith", "assignIn", "defaultsDeep", 
        "mixin", "cloneDeep", "applyToDefaults", "assignDeep"
    }
    
    # Functions that create objects with null prototypes, which are safer
    # because they don't have a prototype chain to pollute.
    SAFE_TARGET_CREATORS = {"Object.create"}
    
    def __init__(self, verbose: bool = False):
        """
        Initialize the analyzer with empty state.
        
        Sets up all the data structures needed for tracking sources, sinks,
        and vulnerabilities across multiple files.
        
        Args:
            verbose: If True, print detailed progress information during analysis
        """
        self.verbose = verbose
        self.vulnerabilities: List[Vulnerability] = []
        
        # Track all data sources found across all files
        # Each source entry contains information about where user-controlled
        # data enters the application (e.g., JSON.parse, getAttribute calls)
        self.sources: List[Dict[str, Any]] = []
        
        # Track which variables are tainted (contain untrusted data)
        # Maps variable name to information about its source
        self.tainted_vars: Dict[str, Dict[str, Any]] = {}
        
        # Track all function calls to see which ones receive tainted data
        # This helps us identify source-to-sink flows
        self.function_calls: List[Dict[str, Any]] = []
        
        # Store all ASTs so we can perform cross-file analysis later
        self.all_asts: List[Dict[str, Any]] = []
        
        # Performance optimization: build parent pointers once per AST
        # This allows O(1) lookup of parent nodes instead of traversing
        # the tree every time we need to find a parent
        self.parent_map: Dict[int, Dict[str, Any]] = {}
        
        # Performance optimization: index functions by name for fast lookup
        # Maps function name to list of function nodes (same name can appear
        # in multiple files or multiple times in one file)
        self.func_index: Dict[str, List[Dict[str, Any]]] = {}
        
        # Performance optimization: precompute which functions contain sinks
        # This allows O(1) checking instead of analyzing the function every time
        self.sink_function_names: Set[str] = set()
        
        # Deduplication: track which vulnerabilities we've already reported
        # Uses (file, line, column, type) tuple as the key
        self._seen_vulns: Set[Tuple[str, int, int, str]] = set()
    
    def analyze_ast(self, ast: Dict[str, Any]) -> List[Vulnerability]:
        """
        Analyze an AST for prototype pollution vulnerabilities.
        
        This method processes a single file's AST and looks for vulnerabilities.
        It also stores the AST for later cross-file analysis, which allows
        tracking data flow across multiple files.
        
        Args:
            ast: Parsed AST dictionary from the parser, containing the
                 abstract syntax tree and metadata about the file
            
        Returns:
            List of all vulnerabilities detected so far (across all files)
        """
        # Save this AST so we can analyze it together with other files later
        # This enables cross-file taint tracking
        self.all_asts.append(ast)
        
        if self.verbose:
            print(f"Analyzing AST from {ast.get('file', 'unknown')}")
        
        file_type = ast.get("file_type", "javascript")
        
        # HTML files need special handling because JavaScript is embedded
        # inside script tags or inline event handlers
        if file_type == "html":
            self._analyze_html_for_merge_functions(ast)
        else:
            # For regular JavaScript files, analyze directly
            self._analyze_javascript_code(ast)
        
        return self.vulnerabilities
    
    def finalize_analysis(self) -> None:
        """
        Perform cross-file taint analysis after all files have been analyzed.
        
        This method runs after all individual files have been processed.
        It connects the dots by tracking how data flows from sources in one
        file to sinks in another file. This is crucial for finding real
        vulnerabilities where untrusted data travels across file boundaries.
        
        The analysis happens in three steps:
        1. Build a global map of all sources and tainted variables
        2. Propagate taint through assignments and function calls
        3. Check if any sinks receive tainted data, creating vulnerabilities
        """
        # If we only have one file (or none), there's no cross-file analysis to do
        if len(self.all_asts) <= 1:
            return
        
        if self.verbose:
            print("Performing cross-file taint analysis...")
        
        # First, gather all the sources we found and build a complete picture
        # of which variables are tainted and where they came from
        self._build_global_taint_map()
        
        # Then, trace how tainted data flows through the codebase
        # This includes assignments like "var x = taintedVar" and function
        # calls where tainted variables are passed as arguments
        self._propagate_taint()
        
        # Finally, check if any dangerous operations (sinks) receive tainted data
        # If they do, we've found a source-to-sink flow vulnerability
        self._check_tainted_sinks()
    
    def _analyze_html_for_merge_functions(self, ast: Dict[str, Any]) -> None:
        """
        Analyze HTML file to extract and analyze embedded JavaScript code.
        
        HTML files can contain JavaScript in multiple places: inline scripts,
        script tags, and event handlers. This method extracts all JavaScript
        code and analyzes it for prototype pollution vulnerabilities.
        
        Note: We focus on detecting merge/extend functions in the JavaScript,
        not HTML injection vulnerabilities themselves.
        
        Args:
            ast: Parsed HTML AST dictionary containing extracted JavaScript
        """
        # Check inline scripts (JavaScript code directly in the HTML)
        for inline_script in ast.get("inline_scripts", []):
            self._analyze_javascript_code(inline_script)
        
        # Check script tags (the <script> elements in the HTML)
        for script_tag in ast.get("script_tags", []):
            script_content = script_tag.get("content", "")
            if script_content:
                # Parse the JavaScript code from the script tag
                try:
                    from .parser import JavaScriptParser
                    parser = JavaScriptParser(verbose=self.verbose)
                    script_ast = parser.parse_code(script_content, ast.get("file", ""))
                    self._analyze_javascript_code(script_ast)
                except Exception:
                    # If we can't parse the script, skip it
                    # This might happen with malformed code or unsupported syntax
                    if self.verbose:
                        print(f"Warning: Could not parse script tag at line {script_tag.get('line', 'unknown')}")
    
    
    def _analyze_javascript_code(self, ast: Dict[str, Any]) -> None:
        """
        Analyze all functions in JavaScript code for prototype pollution vulnerabilities.
        
        This method performs a comprehensive analysis of the JavaScript code.
        It doesn't just look for functions with suspicious names - it actually
        examines the logic of every function to see if it's vulnerable.
        
        The analysis happens in several steps:
        1. Build indexes for fast lookups (parent pointers, function index)
        2. Find all data sources (places where untrusted data enters)
        3. Track which variables get tainted by these sources
        4. Extract all function calls to see data flow
        5. Analyze each function to find sinks (dangerous operations)
        6. Check for direct dangerous property assignments
        
        Args:
            ast: Parsed JavaScript AST dictionary containing the code structure
        """
        # First, build indexes that make later lookups fast
        # This includes parent pointers (for finding variable assignments)
        # and a function index (for quickly finding functions by name)
        self._index_ast(ast)
        
        # Find all places where untrusted data enters the application
        # This includes JSON.parse calls, DOM attribute reads, etc.
        self._detect_sources(ast)
        
        # Mark variables as tainted when they're assigned from sources
        # For example, if we see "var x = JSON.parse(data)", we mark x as tainted
        self._track_initial_taint(ast)
        
        # Extract all function calls so we can track how data flows
        # through function parameters
        self._extract_function_calls(ast)
        
        # Now analyze every function to see if it contains dangerous operations
        # These are called "sinks" - places where tainted data could cause problems
        functions = ast.get("functions", [])
        for func in functions:
            self._check_function_vulnerability(func, ast)
        
        # Also check for direct assignments to dangerous properties
        # These are obvious vulnerabilities like "obj.__proto__ = something"
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
            node = f.get("ast_node") or self._traverse_ast_for_function(ast, f.get("name", ""), f.get("line", 0))
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
        Recursively build a map from each node to its parent.
        
        This creates a bidirectional relationship: we can go from parent to child
        (normal AST structure) and from child to parent (using this map).
        The parent map uses Python's id() function as the key, which gives us
        O(1) lookup time.
        
        Args:
            node: Current AST node being processed
            parent: The parent node of the current node (None if this is the root)
        """
        if not isinstance(node, dict):
            return
        
        # Record this node's parent if it has one
        if parent is not None:
            self.parent_map[id(node)] = parent
        
        # Recursively process all children
        for k, v in node.items():
            # Skip metadata fields that aren't part of the actual AST structure
            if k in ("loc", "range", "leadingComments", "trailingComments"):
                continue
            
            # Process dictionary children (nested nodes)
            if isinstance(v, dict):
                self._build_parent_map(v, node)
            # Process list children (arrays of nodes)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        self._build_parent_map(item, node)
    
    def _detect_sources(self, ast: Dict[str, Any]) -> None:
        """
        Find all places where untrusted data enters the application.
        
        A "source" is any point where user-controlled or untrusted data
        enters the codebase. This includes:
        - JSON.parse() calls that parse user-provided JSON strings
        - DOM attribute reads (getAttribute, dataset properties)
        - Query selectors that might return user-controlled elements
        - Form input values, URL parameters, etc.
        
        Once we identify sources, we can track how this untrusted data
        flows through the code to see if it reaches dangerous operations.
        
        Args:
            ast: Parsed AST dictionary containing the code structure
        """
        ast_root = ast.get("ast")
        if not ast_root:
            return
        
        filename = ast.get("file", "unknown")
        # Recursively search the AST for source patterns
        self._find_sources_in_ast(ast_root, None, filename)
        
        # Also check if the parser already found some JSON.parse calls
        # The parser sometimes extracts these separately, so we add them here too
        for json_call in ast.get("json_parse_calls", []):
            self.sources.append({
                "type": "json_parse",
                "line": json_call.get("line"),
                "column": json_call.get("column"),
                "code": json_call.get("code", ""),
                "variable": None,  # We'll try to extract the variable name from AST later
                "file": filename,
            })
    
    def _find_sources_in_ast(self, node: Any, parent: Optional[Any] = None, filename: str = "unknown") -> None:
        """
        Recursively search the AST to find all data sources.
        
        This method walks through the AST tree looking for patterns that indicate
        untrusted data is entering the application. When it finds a source, it
        records information about where it is and what variable it's assigned to.
        
        Args:
            node: Current AST node being examined
            parent: The parent node of the current node (used to find variable assignments)
            filename: Name of the file being analyzed (for reporting)
        """
        if not isinstance(node, dict):
            return
        
        node_type = node.get("type")
        
        # Check if this is a function call (which might be a source)
        if node_type == "CallExpression":
            callee = node.get("callee", {})
            callee_name = self._get_function_name_from_ast(callee)
            
            # JSON.parse() is a common source - it parses user-provided JSON strings
            if callee_name == "JSON.parse":
                # Try to find what variable this is assigned to
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
            
            # DOM attribute access methods can return user-controlled data
            # Examples: element.getAttribute('data-config'), element.dataset.config
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
            
            # Query selectors can return elements that contain user-controlled attributes
            # These are often used together with getAttribute, so we track them too
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
        
        # Check if this is a property access that reads user input
        # Examples: inputElement.value, textarea.textContent, div.innerHTML
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
        
        # Recursively search all child nodes
        # We pass the current node as the parent so children can find their parent
        for key, value in node.items():
            # Skip metadata fields that don't contain code structure
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
        Find the variable name that a source is assigned to.
        
        When we find a source like "JSON.parse(data)", we need to know what
        variable it's assigned to. This method walks up the AST tree using
        parent pointers to find the nearest variable declaration or assignment.
        
        Examples:
        - "var x = JSON.parse(data)" -> returns "x"
        - "x = JSON.parse(data)" -> returns "x"
        - "JSON.parse(data)" (not assigned) -> returns None
        
        Args:
            node: AST node representing the source (usually a CallExpression)
            parent: Parent node if we already know it (otherwise we look it up)
            
        Returns:
            The name of the variable the source is assigned to, or None if not assigned
        """
        cur = node
        # Start with the parent if provided, otherwise look it up in our map
        if parent is None:
            parent = self.parent_map.get(id(cur))
        
        # Walk up the tree until we find a variable declaration or assignment
        while parent:
            ptype = parent.get("type")
            
            # Found a variable declaration like "var x = ..."
            if ptype == "VariableDeclarator":
                var_id = parent.get("id", {})
                if var_id.get("type") == "Identifier":
                    return var_id.get("name")
                return None
            
            # Found an assignment like "x = ..."
            if ptype == "AssignmentExpression":
                left = parent.get("left", {})
                if left.get("type") == "Identifier":
                    return left.get("name")
                return None
            
            # Keep walking up the tree
            cur = parent
            parent = self.parent_map.get(id(cur))
        
        return None
    
    def _get_object_name_from_ast(self, member_expr: Dict[str, Any]) -> Optional[str]:
        """
        Extract the object name from a property access expression.
        
        This method handles simple cases like "obj.property" (returns "obj")
        and nested cases like "document.getElementById" (returns "document").
        
        Args:
            member_expr: AST node representing a MemberExpression
            
        Returns:
            The name of the object being accessed, or None if it can't be determined
        """
        if member_expr.get("type") != "MemberExpression":
            return None
        
        obj = member_expr.get("object", {})
        if obj.get("type") == "Identifier":
            return obj.get("name")
        elif obj.get("type") == "MemberExpression":
            # Handle nested property access like document.getElementById
            # Recursively extract the base object name
            return self._get_object_name_from_ast(obj)
        
        return None
    
    def _track_initial_taint(self, ast: Dict[str, Any]) -> None:
        """
        Mark variables as tainted when they're assigned from sources.
        
        When we find a source like "var x = JSON.parse(data)", we mark
        the variable "x" as tainted. This allows us to track how untrusted
        data flows through the codebase.
        
        Args:
            ast: Parsed AST dictionary containing the code structure
        """
        ast_root = ast.get("ast")
        if not ast_root:
            return
        
        # Extract all variable assignments and mark tainted ones
        self._extract_variable_assignments(ast_root, ast.get("file", "unknown"))
    
    def _extract_function_calls(self, ast: Dict[str, Any]) -> None:
        """
        Extract all function calls to track how data flows through functions.
        
        We need to know which functions are called and what arguments they receive.
        This helps us determine if tainted data is passed to vulnerable functions.
        
        Args:
            ast: Parsed AST dictionary containing the code structure
        """
        ast_root = ast.get("ast")
        if not ast_root:
            return
        
        # Find all function calls in the code
        self._find_function_calls(ast_root, ast.get("file", "unknown"))
    
    def _find_function_calls(self, node: Any, filename: str, parent: Optional[Any] = None) -> None:
        """
        Recursively find all function call expressions in the AST.
        
        For each function call, we extract:
        - The function name being called
        - The arguments passed to it (and whether they're tainted)
        - What variable the result is assigned to (if any)
        
        This information is crucial for tracking how tainted data flows
        through function calls.
        
        Args:
            node: Current AST node being examined
            filename: Name of the file being analyzed
            parent: Parent node of the current node (used to find assignments)
        """
        if not isinstance(node, dict):
            return
        
        node_type = node.get("type")
        
        # Found a function call
        if node_type == "CallExpression":
            callee = node.get("callee", {})
            func_name = self._get_function_name_from_ast(callee)
            args = node.get("arguments", [])
            
            # Analyze each argument to see if it's tainted
            # Arguments can be variables, expressions, or even direct source calls
            arg_info = []
            for arg in args:
                arg_var = None
                is_direct_source = False
                source_type = None
                
                # Simple variable argument: func(x)
                if arg.get("type") == "Identifier":
                    arg_var = arg.get("name")
                # Property access argument: func(obj.prop)
                elif arg.get("type") == "MemberExpression":
                    obj = arg.get("object", {})
                    if obj.get("type") == "Identifier":
                        arg_var = obj.get("name")
                # Direct source call as argument: func(JSON.parse(data))
                elif arg.get("type") == "CallExpression":
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
            
            # Check if the function call result is assigned to a variable
            # This helps us track taint propagation: "var x = func(tainted)"
            assigned_var = None
            if parent and parent.get("type") == "VariableDeclarator":
                var_id = parent.get("id", {})
                if var_id.get("type") == "Identifier":
                    assigned_var = var_id.get("name")
            elif parent and parent.get("type") == "AssignmentExpression":
                left = parent.get("left", {})
                if left.get("type") == "Identifier":
                    assigned_var = left.get("name")
            
            # Record this function call for later analysis
            self.function_calls.append({
                "function": func_name,
                "arguments": arg_info,
                "assigned_to": assigned_var,
                "line": node.get("loc", {}).get("start", {}).get("line"),
                "file": filename,
                "node": node,
            })
        
        # Recursively search all child nodes for more function calls
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
        Extract variable assignments and mark tainted variables.
        
        This method looks for variable declarations and assignments, and marks
        variables as tainted if they're assigned from sources. It also handles
        taint propagation when a tainted variable is assigned to another variable.
        
        Examples:
        - "var x = JSON.parse(data)" -> mark x as tainted
        - "var y = x" where x is tainted -> mark y as tainted too
        
        Args:
            node: AST node to analyze (recursively processes all nodes)
            filename: Name of the file being analyzed
        """
        if not isinstance(node, dict):
            return
        
        node_type = node.get("type")
        
        # Found a variable declaration like "var x = ..."
        if node_type == "VariableDeclarator":
            var_id = node.get("id", {})
            init = node.get("init", {})
            
            if var_id.get("type") == "Identifier":
                var_name = var_id.get("name")
                
                # Check if the initialization is a source (like JSON.parse)
                if init.get("type") == "CallExpression":
                    callee = init.get("callee", {})
                    callee_name = self._get_function_name_from_ast(callee)
                    
                    # JSON.parse is a source - mark the variable as tainted
                    if callee_name == "JSON.parse":
                        self.tainted_vars[var_name] = {
                            "source_type": "json_parse",
                            "source_line": init.get("loc", {}).get("start", {}).get("line"),
                            "source_file": filename,
                            "tainted_at": "variable_declaration",
                        }
                        self._update_source_variable(init, var_name)
                    
                    # DOM attribute access is also a source
                    elif callee_name and ("getAttribute" in callee_name or "dataset" in callee_name):
                        self.tainted_vars[var_name] = {
                            "source_type": "dom_attribute",
                            "source_line": init.get("loc", {}).get("start", {}).get("line"),
                            "source_file": filename,
                            "tainted_at": "variable_declaration",
                        }
                        self._update_source_variable(init, var_name)
                    
                    # Query selectors can return elements with user-controlled attributes
                    elif callee_name and "querySelector" in callee_name:
                        self.tainted_vars[var_name] = {
                            "source_type": "dom_query",
                            "source_line": init.get("loc", {}).get("start", {}).get("line"),
                            "source_file": filename,
                            "tainted_at": "variable_declaration",
                        }
                        self._update_source_variable(init, var_name)
                
                # Handle property access patterns like "var x = element.getAttribute"
                elif init.get("type") == "MemberExpression":
                    obj = init.get("object", {})
                    prop = init.get("property", {})
                    if prop.get("type") == "Identifier" and prop.get("name") in ("getAttribute", "dataset"):
                        self.tainted_vars[var_name] = {
                            "source_type": "dom_attribute",
                            "source_line": init.get("loc", {}).get("start", {}).get("line"),
                            "source_file": filename,
                            "tainted_at": "variable_declaration",
                        }
                
                # Taint propagation: if we assign a tainted variable to a new variable,
                # the new variable is also tainted
                elif init.get("type") == "Identifier":
                    init_var = init.get("name")
                    if init_var in self.tainted_vars:
                        # Copy the taint information and note that it was propagated
                        self.tainted_vars[var_name] = self.tainted_vars[init_var].copy()
                        self.tainted_vars[var_name]["tainted_at"] = "assignment"
                        self.tainted_vars[var_name]["propagated_from"] = init_var
        
        # Also handle assignment expressions like "x = JSON.parse(...)"
        elif node_type == "AssignmentExpression":
            left = node.get("left", {})
            right = node.get("right", {})
            
            if left.get("type") == "Identifier":
                var_name = left.get("name")
                
                # Check if the right side is a source
                if right.get("type") == "CallExpression":
                    callee = right.get("callee", {})
                    callee_name = self._get_function_name_from_ast(callee)
                    
                    if callee_name == "JSON.parse":
                        self.tainted_vars[var_name] = {
                            "source_type": "json_parse",
                            "source_line": right.get("loc", {}).get("start", {}).get("line"),
                            "source_file": filename,
                            "tainted_at": "assignment",
                        }
                        self._update_source_variable(right, var_name)
                    
                    elif callee_name and ("getAttribute" in callee_name or "dataset" in callee_name):
                        self.tainted_vars[var_name] = {
                            "source_type": "dom_attribute",
                            "source_line": right.get("loc", {}).get("start", {}).get("line"),
                            "source_file": filename,
                            "tainted_at": "assignment",
                        }
                        self._update_source_variable(right, var_name)
                
                # Taint propagation: if we assign a tainted variable, propagate the taint
                elif right.get("type") == "Identifier":
                    right_var = right.get("name")
                    if right_var in self.tainted_vars:
                        self.tainted_vars[var_name] = self.tainted_vars[right_var].copy()
                        self.tainted_vars[var_name]["tainted_at"] = "assignment"
                        self.tainted_vars[var_name]["propagated_from"] = right_var
        
        # Recursively process all child nodes to find more assignments
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
        Update a source entry with the variable name it's assigned to.
        
        When we first find a source, we might not know what variable it's
        assigned to yet. Later, when we process variable assignments, we
        can update the source entry with this information.
        
        Args:
            node: AST node representing the source (a CallExpression)
            var_name: Name of the variable the source is assigned to
        """
        node_line = node.get("loc", {}).get("start", {}).get("line")
        # Find the source entry for this line and update it with the variable name
        for source in self.sources:
            if source.get("line") == node_line and source.get("variable") is None:
                source["variable"] = var_name
                break
    
    def _check_function_vulnerability(self, func: Dict[str, Any], ast: Dict[str, Any]) -> None:
        """
        Check if a function contains prototype pollution vulnerabilities.
        
        This method examines the actual logic of a function, not just its name.
        It looks for dangerous operations (sinks) and checks if they're protected
        by validation. It also checks if tainted data flows into the function.
        
        Args:
            func: Dictionary containing function information (name, line, etc.)
            ast: Full AST dictionary containing the entire file structure
        """
        func_name = func.get("name", "") or ""
        func_line = func.get("line", 0) or 0
        func_column = func.get("column", 0) or 0
        
        # Get the actual AST node for this function
        # The parser might have already extracted it, or we need to find it
        func_ast = func.get("ast_node")
        if not func_ast:
            func_ast = self._find_function_in_ast(ast, func_name, func_line)
        
        if not func_ast:
            return
        
        # Analyze the function's body to find sinks and check for guards
        analysis_result = self._analyze_function_ast(func_ast, func_name, ast)
        
        # If the function is vulnerable, create a vulnerability report
        if analysis_result["is_vulnerable"]:
            func_display_name = func_name if func_name else "(anonymous)"
            severity = analysis_result.get("severity", "high")
            
            # If we know where the tainted data comes from, include that in the message
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
            
            # Include a code snippet to help developers find the issue
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
        Find a function node in the AST by its name and line number.
        
        Sometimes the parser doesn't extract the function node directly,
        so we need to search for it in the AST. This method starts the search.
        
        Args:
            ast: AST dictionary containing the entire file structure
            func_name: Name of the function to find
            line: Line number where the function is defined (for disambiguation)
            
        Returns:
            The function's AST node if found, or None if not found
        """
        ast_root = ast.get("ast")
        if not ast_root:
            return None
        
        return self._traverse_ast_for_function(ast_root, func_name, line)
    
    def _traverse_ast_for_function(self, node: Any, func_name: str, line: int) -> Optional[Dict[str, Any]]:
        """
        Recursively traverse the AST to find a specific function.
        
        This method walks through the AST tree looking for a function with
        the given name. It checks the line number to make sure we find the
        right function if there are multiple functions with the same name.
        
        Args:
            node: Current AST node being examined
            func_name: Name of the function to find
            line: Line number where the function should be (0 to match any line)
            
        Returns:
            The function's AST node if found, or None if not found
        """
        if not isinstance(node, dict):
            return None
        
        node_type = node.get("type")
        node_line = node.get("loc", {}).get("start", {}).get("line")
        
        # Check if this node is a function declaration or expression
        # We support regular functions, function expressions, and arrow functions
        if node_type in ("FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"):
            func_id = node.get("id", {})
            if func_id and func_id.get("name") == func_name:
                # Match by line number if specified, or match any line if line is 0
                if node_line == line or line == 0:
                    return node
        
        # Recursively search all child nodes
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
        Analyze a function's AST to determine if it's vulnerable to prototype pollution.
        
        This method performs semantic analysis of the function body to find:
        1. Dangerous operations (sinks) like property assignments
        2. Whether those operations are protected by validation (guards)
        3. Whether tainted data flows into the function
        
        The combination of these factors determines if the function is vulnerable.
        
        Args:
            func_node: AST node representing the function
            func_name: Name of the function (for reporting)
            ast: Full AST dictionary containing the entire file
            
        Returns:
            Dictionary containing:
            - is_vulnerable: Whether the function is vulnerable
            - severity: Severity level ('high', 'medium', 'low')
            - message: Human-readable description of the vulnerability
            - vulnerability_type: Type of vulnerability found
            - source_info: Information about the source if tainted data flows in
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
        
        # Get the function's parameter names - these are potential entry points
        # for tainted data
        func_params = func_node.get("params", [])
        param_names = [p.get("name") for p in func_params if p.get("type") == "Identifier"]
        
        # Search the function body for dangerous operations (sinks)
        sink_analysis = self._find_prototype_pollution_sinks(func_body, func_name)
        
        # If we found dangerous operations, check if they're protected
        if sink_analysis["has_sink"]:
            has_validation = sink_analysis["has_validation"]
            is_recursive = sink_analysis["is_recursive"]
            
            # Check if tainted data flows into this function through parameters
            source_info = self._check_source_to_sink_flow(func_body, param_names, ast)
            
            # If there's no validation, the function is vulnerable
            if not has_validation:
                result["is_vulnerable"] = True
                result["severity"] = "high"
                result["vulnerability_type"] = "vulnerable_recursive_merge" if is_recursive else "vulnerable_property_assignment"
                result["source_info"] = source_info
                
                # If we found a source-to-sink flow, that's even more serious
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
            # Partial validation is better than none, but still risky
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
        Build a global map of all tainted data across all files.
        
        This method aggregates all the sources and tainted variables we've
        found during individual file analysis. It's called during finalize_analysis
        to prepare for cross-file taint propagation.
        
        Note: The actual collection happens during _detect_sources and
        _track_initial_taint. This method just prints summary information
        if verbose mode is enabled.
        """
        # Sources and tainted variables are already collected during
        # individual file analysis. Here we just print a summary.
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
                for var_name, taint_info in self.tainted_vars.items():
                    source_type = taint_info.get('source_type', 'unknown')
                    source_line = taint_info.get('source_line', '?')
                    source_file = taint_info.get('source_file', 'unknown')
                    tainted_at = taint_info.get('tainted_at', 'unknown')
                    propagated_from = taint_info.get('propagated_from')
                    prop_info = f" (propagated from '{propagated_from}')" if propagated_from else ""
                    print(f"    - '{var_name}': {source_type} source at line {source_line} in {source_file} ({tainted_at}){prop_info}")
            
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
        Propagate taint information through assignments and function calls.
        
        This method implements the core taint analysis algorithm. It tracks
        how tainted data flows through the codebase:
        - When a tainted variable is assigned to another variable
        - When a tainted variable is passed as an argument to a function
        
        This allows us to find source-to-sink flows where untrusted data
        travels from a source to a dangerous operation.
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
                elif arg_var and arg_var in self.tainted_vars:
                    # Tainted variable passed as argument
                    tainted_args.append({
                        "variable": arg_var,
                        "is_direct_source": False,
                        "taint_info": self.tainted_vars[arg_var]
                    })
            
            # If function is a sink and receives tainted data, mark it
            if tainted_args and self._is_sink_function(func_name):
                call["tainted"] = True
                call["tainted_args"] = tainted_args
    
    def _is_sink_function(self, func_name: Optional[str]) -> bool:
        """
        Check if a function is known to contain dangerous operations (sinks).
        
        This method uses precomputed information for fast O(1) lookups.
        Functions are marked as sinks during AST indexing if they contain
        dangerous operations like property assignments without validation.
        
        We also check for common library function names that typically
        perform merge/extend operations (like jQuery.extend, Lodash.merge).
        
        Args:
            func_name: Name of the function to check (can include namespaces like "jQuery.extend")
            
        Returns:
            True if the function is known to contain sinks, False otherwise
        """
        if not func_name:
            return False
        
        # Fast lookup using precomputed set
        if func_name in self.sink_function_names:
            return True
        
        # Check if it's a library helper function
        # Extract the last part of the name (e.g., "extend" from "jQuery.extend")
        last = func_name.split(".")[-1]
        return last in self.MERGE_NAME_HINTS
    
    def _check_tainted_sinks(self) -> None:
        """
        Check sinks for tainted data and create source-to-sink vulnerabilities.
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
                            break
    
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
        # Check if any parameter is tainted
        for param_name in param_names:
            if param_name in self.tainted_vars:
                taint_info = self.tainted_vars[param_name]
                return {
                    "type": taint_info.get("source_type", "unknown"),
                    "line": taint_info.get("source_line"),
                    "file": taint_info.get("source_file"),
                    "variable": param_name,
                }
        
        # Check if function body uses tainted variables
        used_vars = self._extract_variable_usage(func_body)
        for var_name in used_vars:
            if var_name in self.tainted_vars:
                taint_info = self.tainted_vars[var_name]
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
        Add a vulnerability to the results list, with deduplication.
        
        This method prevents the same vulnerability from being reported multiple
        times. It uses a combination of file, line, column, and type to create
        a unique key for each vulnerability.
        
        Args:
            severity: Severity level ('high', 'medium', or 'low')
            line: Line number where the vulnerability was found
            column: Column number where the vulnerability was found
            message: Human-readable description of the vulnerability
            code_snippet: The actual code that contains the vulnerability
            vulnerability_type: Type of vulnerability (e.g., 'source_to_sink_pollution')
            file: Path to the file containing the vulnerability
        """
        # Create a unique key for deduplication
        key = (file or "", int(line or 0), int(column or 0), vulnerability_type or "")
        if key in self._seen_vulns:
            return
        
        # Mark this vulnerability as seen
        self._seen_vulns.add(key)
        
        # Add it to the results list
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
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        child = self._find_prototype_pollution_sinks(item, func_name)
                        result["has_sink"] |= child["has_sink"]
                        result["has_validation"] |= child["has_validation"]
                        result["has_partial_validation"] |= child["has_partial_validation"]
                        result["is_recursive"] |= child["is_recursive"]
        
        return result
    
    def _is_guarded(self, sink_node: Dict[str, Any], key_name: Optional[str]) -> Dict[str, bool]:
        """
        Walk ancestors and determine whether the sink is dominated by:
        - A full exclusion check: key !== "__proto__" && key !== "constructor" && key !== "prototype"
        - Or an own-property check: foo.hasOwnProperty(key) OR Object.prototype.hasOwnProperty.call(foo, key)
        
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
                    # hasOwnProperty guard is considered full (prevents proto chain keys)
                    full = True
            
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
    
