"""
Main detector module that coordinates parsing and analysis.

This module provides the high-level API for detecting prototype pollution
vulnerabilities in JavaScript code. It coordinates the parsing of JavaScript
files into abstract syntax trees and then analyzes those trees for security
issues.
"""

import json
from pathlib import Path
from typing import Dict, List, Any

from .parser import JavaScriptParser
from .analysis import PrototypePollutionAnalyzer, TaintFinding


class PrototypePollutionDetector:
    """
    Main detector class for prototype pollution vulnerabilities.
    
    This class serves as the entry point for the detection tool. It coordinates
    the parsing of JavaScript files into abstract syntax trees and then
    analyzes those trees to find prototype pollution vulnerabilities.
    
    The detector can analyze individual files or entire directories, and it
    supports cross-file analysis to track data flow across multiple files.
    """
    
    def __init__(self, verbose: bool = False):
        """
        Initialize the detector with a parser and analyzer.
        
        Creates the necessary components for parsing JavaScript code and
        analyzing it for vulnerabilities. Both components share the same
        verbosity setting.
        
        Args:
            verbose: If True, print detailed progress information during analysis
        """
        self.verbose = verbose
        self.parser = JavaScriptParser(verbose=verbose)
        self.analyzer = PrototypePollutionAnalyzer(verbose=verbose)
    
    def analyze(self, path: Path) -> Dict[str, Any]:
        """
        Analyze a JavaScript file or directory for prototype pollution vulnerabilities.
        
        This is the main entry point for analysis. It automatically detects
        whether the path is a file or directory and calls the appropriate
        analysis method.
        
        Args:
            path: Path to a JavaScript file or directory containing JavaScript files
            
        Returns:
            Dictionary containing analysis results with vulnerabilities found
            
        Raises:
            ValueError: If the path doesn't exist or is neither a file nor directory
        """
        if path.is_file():
            return self._analyze_file(path)
        elif path.is_dir():
            return self._analyze_directory(path)
        else:
            raise ValueError(f"Invalid path: {path}")
    
    def _analyze_file(self, file_path: Path) -> Dict[str, Any]:
        """
        Analyze a single JavaScript or HTML file for vulnerabilities.
        
        This method handles the analysis of a single file. It first checks
        if the file type is supported, then parses it into an AST, and
        finally analyzes the AST for prototype pollution vulnerabilities.
        
        Args:
            file_path: Path to the JavaScript or HTML file to analyze
            
        Returns:
            Dictionary containing:
            - file: Path to the analyzed file
            - findings: List of finding dictionaries
            - finding_count: Number of findings detected
            - skipped: True if file was skipped (with reason)
            - error: Error message if analysis failed
        """
        if self.verbose:
            print(f"Analyzing file: {file_path}")
        
        # Only process supported file types
        if file_path.suffix not in {".js", ".jsx", ".mjs", ".cjs", ".html", ".htm"}:
            if self.verbose:
                print(f"Skipping unsupported file: {file_path}")
            return {
                "file": str(file_path),
                "skipped": True,
                "reason": "Not a JavaScript or HTML file",
            }
        
        try:
            # Parse the file into an abstract syntax tree
            ast = self.parser.parse_file(file_path)
            
            # Analyze the AST for taint findings
            findings = self.analyzer.analyze_ast(ast)
            
            # Convert finding objects to dictionaries for JSON serialization
            return {
                "file": str(file_path),
                "findings": [
                    {
                        "severity": f.severity,
                        "line": f.line,
                        "column": f.column,
                        "message": f.message,
                        "code_snippet": f.code_snippet,
                        "type": f.finding_type,
                    }
                    for f in findings
                ],
                "finding_count": len(findings),
            }
        
        except Exception as e:
            # If analysis fails, return error information instead of crashing
            return {
                "file": str(file_path),
                "error": str(e),
            }
    
    def _analyze_directory(self, dir_path: Path) -> Dict[str, Any]:
        """
        Analyze all JavaScript files in a directory recursively.
        
        This method performs a two-pass analysis:
        1. First pass: Analyze each file individually and collect ASTs
        2. Second pass: Perform cross-file taint analysis to find vulnerabilities
           where data flows from sources in one file to sinks in another
        
        Args:
            dir_path: Path to the directory containing JavaScript files
            
        Returns:
            Dictionary containing:
            - directory: Path to the analyzed directory
            - files: List of analysis results for each file
            - total_vulnerabilities: Total number of vulnerabilities found across all files
        """
        if self.verbose:
            print(f"Analyzing directory: {dir_path}")
        
        results = {
            "directory": str(dir_path),
            "files": [],
            "total_findings": 0,
        }
        
        # Find all JavaScript and HTML files recursively
        js_files = []
        for pattern in ["**/*.js", "**/*.jsx", "**/*.mjs", "**/*.cjs", "**/*.html", "**/*.htm"]:
            js_files.extend(dir_path.glob(pattern))
        
        # First pass: Analyze each file individually
        # This collects ASTs and finds file-local vulnerabilities
        for js_file in js_files:
            file_result = self._analyze_file(js_file)
            results["files"].append(file_result)
        
        # Second pass: Perform cross-file taint analysis
        # This finds vulnerabilities where data flows across file boundaries
        self.analyzer.finalize_analysis()
        
        # Get all findings detected (including cross-file ones)
        final_findings = self.analyzer.findings
        results["total_findings"] = len(final_findings)
        
        # Update each file's results with the final findings list
        # We match findings to files using the file path stored in each finding
        for file_result in results["files"]:
            file_path = file_result.get("file", "")
            file_findings = []
            for f in final_findings:
                # Match findings to files by checking the file attribute
                if hasattr(f, 'file') and f.file == file_path:
                    file_findings.append(f)
                # Fallback: check if file path appears in code snippet or message
                elif file_path in str(f.code_snippet) or file_path in f.message:
                    file_findings.append(f)
            
            # Update the file result with matched findings
            file_result["findings"] = [
                {
                    "severity": f.severity,
                    "line": f.line,
                    "column": f.column,
                    "message": f.message,
                    "code_snippet": f.code_snippet,
                    "type": f.finding_type,
                }
                for f in file_findings
            ]
            file_result["finding_count"] = len(file_findings)
        
        return results
    
    def print_results(self, results: Dict[str, Any]) -> None:
        """
        Print analysis results to stdout in a human-readable format.
        
        This method formats the analysis results nicely for console output,
        making it easy to see which files have vulnerabilities and what
        those vulnerabilities are.
        
        Args:
            results: Analysis results dictionary from analyze() method
        """
        if "directory" in results:
            print(f"\n=== Analysis Results for {results['directory']} ===\n")
            print(f"Files analyzed: {len(results['files'])}")
            print(f"Total findings detected: {results['total_findings']}\n")
            
            for file_result in results["files"]:
                if file_result.get("skipped"):
                    continue
                
                if "error" in file_result:
                    print(f"[ERROR] {file_result['file']}: Error - {file_result['error']}")
                elif file_result["finding_count"] > 0:
                    print(f"[WARNING] {file_result['file']}: {file_result['finding_count']} finding(s)")
                    for vuln in file_result["vulnerabilities"]:
                        print(f"   [{vuln['severity'].upper()}] Line {vuln['line']}: {vuln['message']}")
                else:
                    print(f"[OK] {file_result['file']}: No vulnerabilities detected")
        else:
            # Single file result
            if results.get("skipped"):
                print(f"Skipped: {results['reason']}")
            elif "error" in results:
                print(f"Error: {results['error']}")
            else:
                print(f"\n=== Analysis Results for {results['file']} ===\n")
                print(f"Findings detected: {results['finding_count']}\n")
                
                for vuln in results["vulnerabilities"]:
                    print(f"[{vuln['severity'].upper()}] Line {vuln['line']}, Column {vuln['column']}")
                    print(f"Type: {vuln['type']}")
                    print(f"Message: {vuln['message']}")
                    if vuln['code_snippet']:
                        print(f"Code: {vuln['code_snippet']}")
                    print()
    
    def save_results(self, results: Dict[str, Any], output_path: Path) -> None:
        """
        Save analysis results to a JSON file.
        
        This method serializes the analysis results to JSON format, making
        it easy to process the results programmatically or share them with
        other tools.
        
        Args:
            results: Analysis results dictionary from analyze() method
            output_path: Path where the JSON file should be saved
        """
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
        
        if self.verbose:
            print(f"Results saved to {output_path}")
