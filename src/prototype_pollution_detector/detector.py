"""
Main detector module that coordinates parsing and analysis.

This module provides the high-level API for the prototype pollution
detection tool.
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional

from .parser import JavaScriptParser
from .analysis import PrototypePollutionAnalyzer, Vulnerability


class PrototypePollutionDetector:
    """
    Main detector class for prototype pollution vulnerabilities.
    
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
    
    def analyze(self, path: Path) -> Dict[str, Any]:
        """
        Analyze a JavaScript file or directory for prototype pollution.
        
        Args:
            path: Path to a JavaScript file or directory
            
        Returns:
            Dictionary containing analysis results
            
        Raises:
            ValueError: If the path is invalid
        """
        if path.is_file():
            return self._analyze_file(path)
        elif path.is_dir():
            return self._analyze_directory(path)
        else:
            raise ValueError(f"Invalid path: {path}")
    
    def _analyze_file(self, file_path: Path) -> Dict[str, Any]:
        """
        Analyze a single JavaScript file.
        
        Args:
            file_path: Path to the JavaScript file
            
        Returns:
            Dictionary containing analysis results
        """
        if self.verbose:
            print(f"Analyzing file: {file_path}")
        
        # Check file extension
        if file_path.suffix not in {".js", ".jsx", ".mjs", ".cjs"}:
            if self.verbose:
                print(f"Skipping non-JavaScript file: {file_path}")
            return {
                "file": str(file_path),
                "skipped": True,
                "reason": "Not a JavaScript file",
            }
        
        try:
            # Parse the file
            ast = self.parser.parse_file(file_path)
            
            # Analyze for vulnerabilities
            vulnerabilities = self.analyzer.analyze_ast(ast)
            
            return {
                "file": str(file_path),
                "vulnerabilities": [
                    {
                        "severity": v.severity,
                        "line": v.line,
                        "column": v.column,
                        "message": v.message,
                        "code_snippet": v.code_snippet,
                        "type": v.vulnerability_type,
                    }
                    for v in vulnerabilities
                ],
                "vulnerability_count": len(vulnerabilities),
            }
        
        except Exception as e:
            return {
                "file": str(file_path),
                "error": str(e),
            }
    
    def _analyze_directory(self, dir_path: Path) -> Dict[str, Any]:
        """
        Analyze all JavaScript files in a directory recursively.
        
        Args:
            dir_path: Path to the directory
            
        Returns:
            Dictionary containing analysis results for all files
        """
        if self.verbose:
            print(f"Analyzing directory: {dir_path}")
        
        results = {
            "directory": str(dir_path),
            "files": [],
            "total_vulnerabilities": 0,
        }
        
        # Find all JavaScript files
        js_files = []
        for pattern in ["**/*.js", "**/*.jsx", "**/*.mjs", "**/*.cjs"]:
            js_files.extend(dir_path.glob(pattern))
        
        # Analyze each file
        for js_file in js_files:
            file_result = self._analyze_file(js_file)
            results["files"].append(file_result)
            
            if "vulnerability_count" in file_result:
                results["total_vulnerabilities"] += file_result["vulnerability_count"]
        
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
            print(f"Total vulnerabilities found: {results['total_vulnerabilities']}\n")
            
            for file_result in results["files"]:
                if file_result.get("skipped"):
                    continue
                
                if "error" in file_result:
                    print(f"❌ {file_result['file']}: Error - {file_result['error']}")
                elif file_result["vulnerability_count"] > 0:
                    print(f"⚠️  {file_result['file']}: {file_result['vulnerability_count']} vulnerability(ies)")
                    for vuln in file_result["vulnerabilities"]:
                        print(f"   [{vuln['severity'].upper()}] Line {vuln['line']}: {vuln['message']}")
                else:
                    print(f"✅ {file_result['file']}: No vulnerabilities detected")
        else:
            # Single file result
            if results.get("skipped"):
                print(f"Skipped: {results['reason']}")
            elif "error" in results:
                print(f"Error: {results['error']}")
            else:
                print(f"\n=== Analysis Results for {results['file']} ===\n")
                print(f"Vulnerabilities found: {results['vulnerability_count']}\n")
                
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
        
        Args:
            results: Analysis results dictionary
            output_path: Path to save the results
        """
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
        
        if self.verbose:
            print(f"Results saved to {output_path}")
