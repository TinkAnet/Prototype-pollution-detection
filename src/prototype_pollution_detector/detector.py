"""
Main detector module that coordinates parsing and analysis.

This module provides the high-level API for the prototype pollution
detection tool.
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional

from .parser import JavaScriptParser
from .analysis import PrototypePollutionAnalyzer, Finding
from .validate import DynamicValidator


class PrototypePollutionDetector:
    """
    Main detector class for prototype pollution findings.
    
    This class coordinates the parsing and analysis of JavaScript code
    to detect potential prototype pollution issues.
    """
    
    def __init__(self, verbose: bool = False):
        """
        Initialize the detector.
        
        Args:
            verbose: Enable verbose output
        """
        self.verbose = verbose
        self.parser = JavaScriptParser(verbose=verbose)
        self.analyzer = PrototypePollutionAnalyzer(verbose=verbose)
        self.dynamic_validator = DynamicValidator(verbose=verbose)
    
    def analyze(self, path: Path, dynamic_verify: bool = False) -> Dict[str, Any]:
        """
        Analyze a JavaScript file or directory for prototype pollution.
        
        Args:
            path: Path to a JavaScript file or directory
            dynamic_verify: Whether to attempt dynamic verification of findings
            
        Returns:
            Dictionary containing analysis results
            
        Raises:
            ValueError: If the path is invalid
        """
        if path.is_file():
            return self._analyze_file(path, dynamic_verify)
        elif path.is_dir():
            return self._analyze_directory(path, dynamic_verify)
        else:
            raise ValueError(f"Invalid path: {path}")
    
    def _analyze_file(self, file_path: Path, dynamic_verify: bool = False) -> Dict[str, Any]:
        """
        Analyze a single JavaScript file.
        
        Args:
            file_path: Path to the JavaScript file
            dynamic_verify: Whether to attempt dynamic verification
            
        Returns:
            Dictionary containing analysis results
        """
        if self.verbose:
            print(f"Analyzing file: {file_path}")
        
        # Check file extension
        if file_path.suffix not in {".js", ".jsx", ".mjs", ".cjs", ".html", ".htm"}:
            if self.verbose:
                print(f"Skipping unsupported file: {file_path}")
            return {
                "file": str(file_path),
                "skipped": True,
                "reason": "Not a JavaScript or HTML file",
            }
        
        try:
            # Parse the file
            ast = self.parser.parse_file(file_path)
            
            # Analyze for findings
            findings = self.analyzer.analyze_ast(ast)
            
            result = {
                "file": str(file_path),
                "findings": [
                    {
                        "severity": v.severity,
                        "line": v.line,
                        "column": v.column,
                        "message": v.message,
                        "code_snippet": v.code_snippet,
                        "type": v.finding_type,
                    }
                    for v in findings
                ],
                "finding_count": len(findings),
            }
            
            # Perform dynamic verification if requested
            if dynamic_verify:
                if self.verbose:
                    print(f"Performing dynamic verification for {file_path}")
                
                # We usually only want to dynamically verify if it looks like a library 
                # or if static analysis found something, but for now we can run it if requested.
                dynamic_result = self.dynamic_validator.validate(file_path)
                result["dynamic_verification"] = dynamic_result
                
                if dynamic_result.get("vulnerable"):
                     result["confirmed_vulnerable"] = True
            
            return result
        
        except Exception as e:
            return {
                "file": str(file_path),
                "error": str(e),
            }
    
    def _analyze_directory(self, dir_path: Path, dynamic_verify: bool = False) -> Dict[str, Any]:
        """
        Analyze all JavaScript files in a directory recursively.
        
        Args:
            dir_path: Path to the directory
            dynamic_verify: Whether to attempt dynamic verification
            
        Returns:
            Dictionary containing analysis results for all files
        """
        if self.verbose:
            print(f"Analyzing directory: {dir_path}")
        
        results = {
            "directory": str(dir_path),
            "files": [],
            "total_findings": 0,
        }
        
        # Find all JavaScript and HTML files
        js_files = []
        for pattern in ["**/*.js", "**/*.jsx", "**/*.mjs", "**/*.cjs", "**/*.html", "**/*.htm"]:
            js_files.extend(dir_path.glob(pattern))
        
        # First pass: Analyze each file
        for js_file in js_files:
            file_result = self._analyze_file(js_file, dynamic_verify)
            results["files"].append(file_result)
            if file_result.get("finding_count", 0) > 0:
                 # Static analysis updates are handled here, but cross-file is separate
                 pass
        
        # Second pass: Perform cross-file taint analysis (static only for now)
        self.analyzer.finalize_analysis()
        
        # Update results with final findings
        final_vulns = self.analyzer.findings
        results["total_findings"] = len(final_vulns)
        
        # Update file results with final findings
        for file_result in results["files"]:
            file_path = file_result.get("file", "")
            
            # If we already have results, we update the vulnerability list
            # Be careful not to overwrite dynamic verification results
            
            file_vulns = []
            for v in final_vulns:
                if hasattr(v, 'file') and v.file == file_path:
                    file_vulns.append(v)
                elif file_path in str(v.code_snippet) or file_path in v.message:
                    file_vulns.append(v)
            
            file_result["findings"] = [
                {
                    "severity": v.severity,
                    "line": v.line,
                    "column": v.column,
                    "message": v.message,
                    "code_snippet": v.code_snippet,
                    "type": v.finding_type,
                }
                for v in file_vulns
            ]
            file_result["finding_count"] = len(file_vulns)
        
        return results
    
    def print_results(self, results: Dict[str, Any]) -> None:
        """
        Print analysis results to stdout in a human-readable format.
        
        Args:
            results: Analysis results dictionary
        """
        if "directory" in results:
            print(f"\n=== Analysis Results for {results['directory']} ===\n")
            print(f"Files analyzed: {len(results['files'])}")
            print(f"Total findings found (Static): {results['total_findings']}\n")
            
            for file_result in results["files"]:
                self._print_single_file_result(file_result)
        else:
            # Single file result
            self._print_single_file_result(results, header=True)

    def _print_single_file_result(self, result: Dict[str, Any], header: bool = False) -> None:
        """Helper to print result for a single file."""
        file_path = result.get("file", "Unknown")
        
        if header:
            print(f"\n=== Analysis Results for {file_path} ===\n")
            
        if result.get("skipped"):
            if header: print(f"Skipped: {result['reason']}")
            return
            
        if "error" in result:
            print(f"[-] {file_path}: Error - {result['error']}")
            return

        vuln_count = result.get("finding_count", 0)
        dynamic = result.get("dynamic_verification")
        
        status_symbol = "[+]"
        status_msg = "No findings detected"
        
        if vuln_count > 0:
            status_symbol = "[!]"
            status_msg = f"{vuln_count} vulnerability(ies) (Static)"
        
        if dynamic:
            if dynamic.get("vulnerable"):
                status_symbol = "[!!!]"
                status_msg += " | CONFIRMED VULNERABLE via Dynamic Check"
            elif dynamic.get("error"):
                 status_msg += f" | Dynamic Check Failed: {dynamic['error']}"
            else:
                 status_msg += " | Dynamic Check: Safe/Not Vulnerable"
        
        print(f"{status_symbol} {file_path}: {status_msg}")
                
        for vuln in result.get("findings", []):
            print(f"   [{vuln['severity'].upper()}] Line {vuln['line']}: {vuln['message']}")
            if header and vuln['code_snippet']:
                print(f"     Code: {vuln['code_snippet']}")
        
        if header and dynamic:
             print(f"\nDynamic Verification Output:\n{dynamic.get('output', '')}")
             if dynamic.get('error'):
                 print(f"Error: {dynamic['error']}")
    
    def save_results(self, results: Dict[str, Any], output_path: Path) -> None:
        """
        Save analysis results to a JSON file.
        
        Args:
            results: Analysis results dictionary
            output_path: Path to save the results
        """
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
        
        if self.verbose:
            print(f"Results saved to {output_path}")
