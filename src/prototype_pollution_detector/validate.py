import os
import sys
import json
import shutil
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional, List

class DynamicValidator:
    """
    Dynamic validator for prototype pollution vulnerabilities.
    Executes the target JavaScript code in a controlled environment with a payload
    to check if it's actually vulnerable.
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def validate(self, file_path: Path) -> Dict[str, Any]:
        """
        Validate if a JavaScript file is vulnerable to prototype pollution
        by dynamically executing it with a payload.
        
        Args:
            file_path: Path to the JavaScript file
            
        Returns:
            Dictionary containing validation results
        """
        file_path = Path(file_path).resolve()
        if not file_path.exists():
            return {"error": "File not found", "vulnerable": False}

        # Create a harness file in the same directory to handle relative imports correctly
        # We use a random name to avoid conflicts
        import uuid
        harness_name = f"harness_{uuid.uuid4().hex[:8]}.js"
        harness_path = file_path.parent / harness_name
        
        try:
            # Generate the harness code
            harness_code = self._generate_harness(file_path.name)
            
            with open(harness_path, 'w') as f:
                f.write(harness_code)
            
            # Execute with node
            if self.verbose:
                print(f"Executing harness: {harness_path}")
                
            # Run node with a timeout to prevent infinite loops
            result = subprocess.run(
                ["node", harness_name],
                cwd=file_path.parent,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            stdout = result.stdout.strip()
            stderr = result.stderr.strip()
            
            if self.verbose:
                print(f"Stdout: {stdout}")
                if stderr:
                    print(f"Stderr: {stderr}")
            
            is_vulnerable = "VULNERABLE" in stdout
            error = None
            if "ERROR:" in stdout:
                error = stdout.split("ERROR:")[1].strip()
            elif result.returncode != 0:
                error = stderr if stderr else "Unknown execution error"
                
            return {
                "file": str(file_path),
                "vulnerable": is_vulnerable,
                "output": stdout,
                "error": error,
                "dynamic_check_performed": True
            }
            
        except subprocess.TimeoutExpired:
            return {
                "file": str(file_path),
                "vulnerable": False,
                "error": "Execution timed out",
                "dynamic_check_performed": True
            }
        except Exception as e:
            return {
                "file": str(file_path),
                "vulnerable": False,
                "error": str(e),
                "dynamic_check_performed": False
            }
        finally:
            # Clean up
            if harness_path.exists():
                harness_path.unlink()

    def _generate_harness(self, target_filename: str) -> str:
        """
        Generate the JavaScript harness code to test the target file.
        """
        # Escape the filename for JS string
        js_target_filename = json.dumps("./" + target_filename)
        
        return f"""
const path = require('path');
const Module = require('module');


// MOCK ENVIRONMENT


// Mock browser globals
if (typeof global.window === 'undefined') {{
    global.window = global;
    global.self = global;
    global.parent = global;
    global.top = global;
    
    // Add window methods to global
    global.addEventListener = () => {{}};
    global.removeEventListener = () => {{}};
    global.alert = (msg) => {{}};
    global.prompt = () => '';
    global.confirm = () => true;
    global.scrollTo = () => {{}};
    global.requestAnimationFrame = (cb) => setTimeout(cb, 16);
    global.cancelAnimationFrame = (id) => clearTimeout(id);
}}

if (typeof global.document === 'undefined') {{
    global.document = {{
        createElement: () => ({{
            setAttribute: () => {{}},
            appendChild: () => {{}},
            style: {{}},
            children: [],
            tagName: 'DIV',
            nodeName: 'DIV',
            nodeType: 1
        }}),
        getElementById: () => ({{}}),
        getElementsByTagName: () => ([]),
        addEventListener: () => {{}},
        removeEventListener: () => {{}},
        documentElement: {{ style: {{}} }},
        body: {{ style: {{}}, appendChild: () => {{}} }},
        location: {{ href: 'http://localhost', search: '', hash: '' }},
        cookie: '',
        readyState: 'complete'
    }};
}}

if (typeof global.navigator === 'undefined') {{
    global.navigator = {{
        userAgent: 'Node.js Mock',
        appVersion: '1.0',
        platform: 'Node'
    }};
}}

if (typeof global.location === 'undefined') {{
    global.location = global.document.location;
}}

// Mock common libraries
if (typeof global.jQuery === 'undefined') {{
    const jq = function(sel) {{
        // If selected is window/document, return them wrapped?
        // For now, return a chainable object
        return {{
            on: () => jq,
            off: () => jq,
            bind: () => jq,
            click: () => jq,
            find: () => jq,
            css: () => jq,
            attr: () => jq,
            val: () => '',
            length: 0,
            each: (cb) => {{}},
            ready: (cb) => cb(),
            append: () => jq
        }};
    }};
    jq.extend = Object.assign;
    jq.fn = {{ extend: Object.assign }};
    jq.document = global.document;
    jq.isFunction = (obj) => typeof obj === 'function';
    jq.isArray = Array.isArray;
    
    global.jQuery = jq;
    // Don't overwrite $ if it's already defined (e.g. by other libs), but usually safe here
    if (typeof global.$ === 'undefined') {{
        global.$ = jq;
    }}
}}

// Mock missing modules
const originalRequire = Module.prototype.require;
Module.prototype.require = function(id) {{
    try {{
        return originalRequire.call(this, id);
    }} catch (e) {{
        if (e.code === 'MODULE_NOT_FOUND') {{
            // console.log(`[Harness] Mocking missing module: ${{id}}`);
            
            // Return a Proxy that handles any property access graciously
            const noop = () => new Proxy(() => {{}}, proxyHandler);
            const proxyHandler = {{
                get: (target, prop) => {{
                    if (prop === 'default') return new Proxy(() => {{}}, proxyHandler);
                    if (prop === '__esModule') return true;
                    if (prop === 'prototype') return {{}};
                    if (prop === 'call' || prop === 'apply' || prop === 'bind') return Function.prototype[prop];
                    return new Proxy(() => {{}}, proxyHandler);
                }},
                apply: () => new Proxy(() => {{}}, proxyHandler),
                construct: () => new Proxy(() => {{}}, proxyHandler)
            }};
            
            return new Proxy(noop, proxyHandler);
        }}
        throw e;
    }}
}};



// TEST EXECUTION

async function run() {{
    const targetPath = {js_target_filename};
    let lib;
    
    try {{
        // Try CJS require first
        lib = require(targetPath);
    }} catch (e) {{
        try {{
            // Try dynamic import for ESM
            const module = await import(targetPath);
            lib = module.default || module;
        }} catch (e2) {{
            console.log("ERROR: Could not load module: " + e.message + " | " + e2.message);
            process.exit(1);
        }}
    }}

    // Payloads to test
    const payloads = [
        JSON.parse('{{"__proto__":{{"polluted":true}}}}'),
        JSON.parse('{{"constructor":{{"prototype":{{"polluted":true}}}}}}')
    ];
    
    // Helper to reset pollution between tests
    const clean = () => {{
        delete Object.prototype.polluted;
    }};

    // Helper to check status
    const check = () => {{
        return ({{}}).polluted === true;
    }};

    try {{
        for (const payload of payloads) {{
            clean();
            
            // Strategy 1: If it's a function, try calling it as merge(target, source)
            if (typeof lib === 'function') {{
                try {{
                    const target = {{}};
                    lib(target, payload);
                    if (check()) {{
                        console.log("VULNERABLE");
                        return;
                    }}
                }} catch (e) {{}}
                
                clean();
                
                // Strategy 2: Try calling it as merge(source) - e.g. return new object
                try {{
                    lib(payload);
                    if (check()) {{
                        console.log("VULNERABLE");
                        return;
                    }}
                }} catch (e) {{}}
            }} 
            
            // Strategy 3: If it's an object, look for common merge/extend function names
            if (lib && (typeof lib === 'object' || typeof lib === 'function')) {{
                // Comprehensive list of function names (case-sensitive first pass)
                const functionPatterns = [
                    // Merge variants
                    'merge', 'mergeWith', 'mergeDeep', 'deepMerge', 'deepmerge', 
                    'mergeDeeply', 'recursiveMerge', 'smartMerge',
                    
                    // Extend variants
                    'extend', 'extendWith', 'extendDeep', 'deepExtend', 'deepextend',
                    'extendOwn', 'extendRecursive', 'extendDeepWith',
                    
                    // Assign variants
                    'assign', 'assignWith', 'assignDeep', 'deepAssign', 
                    'assignIn', 'assignInWith', 'assignDeepWith',
                    
                    // Defaults variants
                    'defaults', 'defaultsDeep', 'defaultsDeepWith',
                    
                    // Mixin variants
                    'mixin', 'mixinDeep', 'deepMixin', 'mix',
                    
                    // Clone/Copy variants
                    'clone', 'cloneDeep', 'deepClone', 'cloneDeepWith',
                    'copy', 'copyDeep', 'deepCopy', 'deepCopyWith',
                    
                    // Set/Update variants
                    'set', 'setWith', 'deepSet', 'setDeep',
                    'update', 'updateWith', 'deepUpdate', 'updateDeep',
                    
                    // Other common patterns
                    'all', 'recursive', 'apply', 'applyDeep',
                    'combine', 'combineDeep', 'aggregate',
                    'concat', 'concatDeep', 'join', 'joinDeep'
                ];
                
                // Get all properties from the library
                const libProps = Object.keys(lib);
                
                // First pass: exact name matching
                for (const name of functionPatterns) {{
                    if (typeof lib[name] === 'function') {{
                        clean();
                        try {{
                            const target = {{}};
                            lib[name](target, payload);
                            if (check()) {{
                                console.log("VULNERABLE");
                                return;
                            }}
                        }} catch (e) {{}}
                    }}
                }}
                
                // Second pass: case-insensitive matching
                const testedProps = new Set(functionPatterns.map(p => p.toLowerCase()));
                
                for (const prop of libProps) {{
                    if (typeof lib[prop] !== 'function') continue;
                    
                    const propLower = prop.toLowerCase();
                    
                    // Skip if already tested in first pass
                    if (testedProps.has(propLower)) continue;
                    
                    // Check if it matches any pattern (case-insensitive)
                    const matchesPattern = functionPatterns.some(pattern => 
                        pattern.toLowerCase() === propLower
                    );
                    
                    if (matchesPattern) {{
                        clean();
                        try {{
                            const target = {{}};
                            lib[prop](target, payload);
                            if (check()) {{
                                console.log("VULNERABLE");
                                return;
                            }}
                        }} catch (e) {{}}
                        testedProps.add(propLower);
                    }}
                }}
                
                // Third pass: fuzzy regex matching for unknown function names
                const fuzzyPatterns = [
                    /merge/i, /extend/i, /assign/i, /mixin/i, 
                    /clone/i, /copy/i, /defaults/i, /deep/i
                ];
                
                for (const prop of libProps) {{
                    if (typeof lib[prop] !== 'function') continue;
                    if (testedProps.has(prop.toLowerCase())) continue;
                    
                    // Check if property name matches any fuzzy pattern
                    if (fuzzyPatterns.some(pattern => pattern.test(prop))) {{
                        clean();
                        try {{
                            const target = {{}};
                            lib[prop](target, payload);
                            if (check()) {{
                                console.log("VULNERABLE");
                                return;
                            }}
                        }} catch (e) {{}}
                    }}
                }}
            }}
        }}

        if (check()) {{
            console.log("VULNERABLE");
        }} else {{
            console.log("SAFE");
        }}
        
    }} catch (err) {{
        console.log("ERROR: Execution failed: " + err.message);
    }}
}}

run();
"""
