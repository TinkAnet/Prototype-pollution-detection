"""
Batch analyzer for crawled code sources.

This module provides optimized analysis for GitHub-crawled code snippets,
with better aggregation, deduplication, and cross-file analysis.
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from collections import defaultdict
from dataclasses import dataclass, asdict
import hashlib

from .detector import PrototypePollutionDetector


@dataclass
class RepositoryAnalysis:
    """Analysis results for a single repository."""
    repository: str
    files: List[str]
    vulnerabilities: List[Dict[str, Any]]
    total_vulnerabilities: int
    vulnerability_types: Dict[str, int]
    severity_counts: Dict[str, int]
    has_source_to_sink_flows: bool
    analysis_metadata: Dict[str, Any]


@dataclass
class BatchAnalysisResult:
    """Results of batch analysis across multiple repositories."""
    total_repositories: int
    total_files: int
    total_vulnerabilities: int
    repositories: List[RepositoryAnalysis]
    global_statistics: Dict[str, Any]
    unique_vulnerability_patterns: List[Dict[str, Any]]


class BatchAnalyzer:
    """
    Batch analyzer for crawled code sources.
    
    Features:
    - Groups files by repository for cross-file analysis
    - Deduplicates vulnerabilities across repositories
    - Aggregates statistics
    - Identifies unique vulnerability patterns
    """
    
    def __init__(self, verbose: bool = False):
        """
        Initialize the batch analyzer.
        
        Args:
            verbose: Enable verbose output
        """
        self.verbose = verbose
        self.detector = PrototypePollutionDetector(verbose=verbose)
        
        # Deduplication tracking
        self._vulnerability_signatures: Set[str] = set()
        self._code_hashes: Dict[str, str] = {}  # file_path -> hash
    
    def analyze_crawler_sources(
        self,
        sources_dir: Path,
        max_files_per_repo: Optional[int] = None,
        skip_known_patterns: bool = True,
    ) -> BatchAnalysisResult:
        """
        Analyze all crawled code sources.
        
        Args:
            sources_dir: Directory containing crawled sources (organized by repo)
            max_files_per_repo: Maximum files to analyze per repository
            skip_known_patterns: Skip files matching known safe patterns
            
        Returns:
            BatchAnalysisResult with aggregated results
        """
        if self.verbose:
            print(f"Analyzing crawled sources in: {sources_dir}")
        
        # Step 1: Group files by repository
        repo_files = self._group_files_by_repository(sources_dir)
        
        if self.verbose:
            print(f"Found {len(repo_files)} repositories")
            total_files = sum(len(files) for files in repo_files.values())
            print(f"Total files: {total_files}")
        
        # Step 2: Analyze each repository
        repository_results = []
        all_vulnerabilities = []
        
        for repo_name, file_paths in repo_files.items():
            if self.verbose:
                print(f"\nAnalyzing repository: {repo_name} ({len(file_paths)} files)")
            
            repo_result = self._analyze_repository(
                repo_name,
                file_paths,
                max_files=max_files_per_repo,
                skip_known_patterns=skip_known_patterns,
            )
            
            if repo_result:
                repository_results.append(repo_result)
                all_vulnerabilities.extend(repo_result.vulnerabilities)
        
        # Step 3: Aggregate statistics
        global_stats = self._compute_global_statistics(repository_results)
        
        # Step 4: Identify unique vulnerability patterns
        unique_patterns = self._identify_unique_patterns(all_vulnerabilities)
        
        return BatchAnalysisResult(
            total_repositories=len(repository_results),
            total_files=sum(len(r.files) for r in repository_results),
            total_vulnerabilities=len(all_vulnerabilities),
            repositories=repository_results,
            global_statistics=global_stats,
            unique_vulnerability_patterns=unique_patterns,
        )
    
    def _group_files_by_repository(self, sources_dir: Path) -> Dict[str, List[Path]]:
        """
        Group files by repository name.
        
        Expected structure:
        crawler_sources/
          owner1/
            repo1/
              file1.js
              file2.js
          owner2/
            repo2/
              file1.js
        
        Returns:
            Dictionary mapping repo_name -> list of file paths
        """
        repo_files = defaultdict(list)
        
        if not sources_dir.exists():
            return repo_files
        
        # Traverse directory structure
        for owner_dir in sources_dir.iterdir():
            if not owner_dir.is_dir():
                continue
            
            for repo_dir in owner_dir.iterdir():
                if not repo_dir.is_dir():
                    continue
                
                # Repository name: owner/repo
                repo_name = f"{owner_dir.name}/{repo_dir.name}"
                
                # Find all JavaScript/HTML files
                for pattern in ["**/*.js", "**/*.jsx", "**/*.mjs", "**/*.cjs", 
                               "**/*.html", "**/*.htm", "**/*.ts", "**/*.tsx"]:
                    for file_path in repo_dir.glob(pattern):
                        if file_path.is_file():
                            repo_files[repo_name].append(file_path)
        
        return dict(repo_files)
    
    def _analyze_repository(
        self,
        repo_name: str,
        file_paths: List[Path],
        max_files: Optional[int] = None,
        skip_known_patterns: bool = True,
    ) -> Optional[RepositoryAnalysis]:
        """
        Analyze a single repository with cross-file analysis.
        
        Args:
            repo_name: Repository name (owner/repo)
            file_paths: List of file paths in the repository
            max_files: Maximum files to analyze
            skip_known_patterns: Skip known safe patterns
            
        Returns:
            RepositoryAnalysis or None if analysis failed
        """
        # Limit files if specified
        if max_files:
            file_paths = file_paths[:max_files]
        
        # Filter out known safe patterns
        if skip_known_patterns:
            file_paths = [f for f in file_paths if not self._is_known_safe_pattern(f)]
        
        if not file_paths:
            return None
        
        # Create a temporary directory structure for analysis
        # This allows cross-file analysis to work properly
        import tempfile
        import shutil
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Copy files maintaining structure
            analyzed_files = []
            for file_path in file_paths:
                # Create relative path structure
                rel_path = file_path.relative_to(file_path.parents[2])  # Remove owner/repo
                temp_file = temp_path / rel_path
                temp_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(file_path, temp_file)
                analyzed_files.append(str(temp_file))
            
            try:
                # Analyze the repository directory
                # This enables cross-file taint analysis
                analysis_result = self.detector.analyze(temp_path)
                
                # Extract vulnerabilities
                vulnerabilities = []
                for file_result in analysis_result.get("files", []):
                    file_vulns = file_result.get("vulnerabilities", [])
                    for vuln in file_vulns:
                        # Map back to original file path
                        temp_file = file_result.get("file", "")
                        original_file = self._map_to_original_path(temp_file, file_paths)
                        
                        vuln_dict = {
                            "severity": vuln.get("severity"),
                            "line": vuln.get("line"),
                            "column": vuln.get("column"),
                            "message": vuln.get("message"),
                            "code_snippet": vuln.get("code_snippet", "")[:200],  # Limit size
                            "type": vuln.get("type"),
                            "file": original_file,
                        }
                        
                        # Deduplicate by signature
                        signature = self._vulnerability_signature(vuln_dict)
                        if signature not in self._vulnerability_signatures:
                            self._vulnerability_signatures.add(signature)
                            vulnerabilities.append(vuln_dict)
                
                # Compute statistics
                vulnerability_types = defaultdict(int)
                severity_counts = defaultdict(int)
                has_source_to_sink = False
                
                for vuln in vulnerabilities:
                    vuln_type = vuln.get("type", "unknown")
                    severity = vuln.get("severity", "low")
                    vulnerability_types[vuln_type] += 1
                    severity_counts[severity] += 1
                    
                    if "source_to_sink" in vuln_type.lower():
                        has_source_to_sink = True
                
                return RepositoryAnalysis(
                    repository=repo_name,
                    files=[str(f) for f in file_paths],
                    vulnerabilities=vulnerabilities,
                    total_vulnerabilities=len(vulnerabilities),
                    vulnerability_types=dict(vulnerability_types),
                    severity_counts=dict(severity_counts),
                    has_source_to_sink_flows=has_source_to_sink,
                    analysis_metadata={
                        "files_analyzed": len(file_paths),
                        "cross_file_analysis": True,
                    },
                )
            
            except Exception as e:
                if self.verbose:
                    print(f"Error analyzing {repo_name}: {e}")
                return None
    
    def _is_known_safe_pattern(self, file_path: Path) -> bool:
        """
        Check if file matches known safe patterns (e.g., minified, test files).
        
        Args:
            file_path: File path to check
            
        Returns:
            True if file should be skipped
        """
        file_name = file_path.name.lower()
        
        # Skip minified files
        if any(x in file_name for x in [".min.js", ".bundle.js", ".pack.js"]):
            return True
        
        # Skip test files (optional - might want to analyze them)
        # if any(x in file_name for x in ["test", "spec", "__tests__"]):
        #     return True
        
        return False
    
    def _map_to_original_path(self, temp_file: str, original_paths: List[Path]) -> str:
        """
        Map temporary file path back to original path.
        
        Args:
            temp_file: Temporary file path
            original_paths: List of original file paths
            
        Returns:
            Original file path string
        """
        temp_path = Path(temp_file)
        temp_name = temp_path.name
        
        # Find matching original file
        for orig_path in original_paths:
            if orig_path.name == temp_name:
                return str(orig_path)
        
        return temp_file
    
    def _vulnerability_signature(self, vuln: Dict[str, Any]) -> str:
        """
        Generate a signature for vulnerability deduplication.
        
        Args:
            vuln: Vulnerability dictionary
            
        Returns:
            Signature string
        """
        # Create signature from key fields
        key_fields = (
            vuln.get("type", ""),
            vuln.get("message", "")[:100],  # First 100 chars
            vuln.get("file", ""),
            vuln.get("line", 0),
        )
        signature_str = "|".join(str(f) for f in key_fields)
        return hashlib.md5(signature_str.encode()).hexdigest()
    
    def _compute_global_statistics(
        self,
        repository_results: List[RepositoryAnalysis],
    ) -> Dict[str, Any]:
        """
        Compute global statistics across all repositories.
        
        Args:
            repository_results: List of repository analysis results
            
        Returns:
            Dictionary with global statistics
        """
        total_vulns = sum(r.total_vulnerabilities for r in repository_results)
        total_files = sum(len(r.files) for r in repository_results)
        
        # Aggregate vulnerability types
        type_counts = defaultdict(int)
        severity_counts = defaultdict(int)
        repos_with_source_to_sink = 0
        
        for repo_result in repository_results:
            for vuln_type, count in repo_result.vulnerability_types.items():
                type_counts[vuln_type] += count
            
            for severity, count in repo_result.severity_counts.items():
                severity_counts[severity] += count
            
            if repo_result.has_source_to_sink_flows:
                repos_with_source_to_sink += 1
        
        return {
            "total_vulnerabilities": total_vulns,
            "total_files": total_files,
            "average_vulnerabilities_per_repo": (
                total_vulns / len(repository_results) if repository_results else 0
            ),
            "average_vulnerabilities_per_file": (
                total_vulns / total_files if total_files > 0 else 0
            ),
            "vulnerability_types": dict(type_counts),
            "severity_distribution": dict(severity_counts),
            "repositories_with_source_to_sink_flows": repos_with_source_to_sink,
            "repositories_with_vulnerabilities": len([
                r for r in repository_results if r.total_vulnerabilities > 0
            ]),
        }
    
    def _identify_unique_patterns(
        self,
        vulnerabilities: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Identify unique vulnerability patterns across repositories.
        
        Args:
            vulnerabilities: List of all vulnerabilities
            
        Returns:
            List of unique patterns with occurrence counts
        """
        # Group by vulnerability type and message pattern
        pattern_groups = defaultdict(list)
        
        for vuln in vulnerabilities:
            # Create pattern key from type and message
            pattern_key = (
                vuln.get("type", "unknown"),
                vuln.get("message", "")[:150],  # First 150 chars
            )
            pattern_groups[pattern_key].append(vuln)
        
        # Convert to list of patterns
        unique_patterns = []
        for (vuln_type, message_pattern), vulns in pattern_groups.items():
            unique_patterns.append({
                "type": vuln_type,
                "message_pattern": message_pattern,
                "occurrence_count": len(vulns),
                "severity": max((v.get("severity", "low") for v in vulns), 
                              key=lambda s: {"high": 3, "medium": 2, "low": 1}.get(s, 0)),
                "example_files": list(set(v.get("file", "") for v in vulns[:5])),  # First 5 unique files
            })
        
        # Sort by occurrence count
        unique_patterns.sort(key=lambda x: x["occurrence_count"], reverse=True)
        
        return unique_patterns
    
    def save_results(
        self,
        results: BatchAnalysisResult,
        output_file: Path,
        format: str = "json",
    ) -> None:
        """
        Save batch analysis results to file.
        
        Args:
            results: BatchAnalysisResult to save
            output_file: Output file path
            format: Output format ("json" or "jsonl")
        """
        if format == "json":
            # Convert to dictionary
            results_dict = {
                "total_repositories": results.total_repositories,
                "total_files": results.total_files,
                "total_vulnerabilities": results.total_vulnerabilities,
                "repositories": [asdict(r) for r in results.repositories],
                "global_statistics": results.global_statistics,
                "unique_vulnerability_patterns": results.unique_vulnerability_patterns,
            }
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results_dict, f, indent=2, ensure_ascii=False)
        
        elif format == "jsonl":
            # Save as JSONL (one repository per line)
            with open(output_file, 'w', encoding='utf-8') as f:
                for repo in results.repositories:
                    f.write(json.dumps(asdict(repo), ensure_ascii=False) + '\n')
        
        if self.verbose:
            print(f"Results saved to {output_file}")
    
    def print_summary(self, results: BatchAnalysisResult) -> None:
        """
        Print a summary of batch analysis results.
        
        Args:
            results: BatchAnalysisResult to summarize
        """
        print("\n" + "="*80)
        print("Batch Analysis Summary")
        print("="*80)
        
        print(f"\nRepositories analyzed: {results.total_repositories}")
        print(f"Total files: {results.total_files}")
        print(f"Total vulnerabilities: {results.total_vulnerabilities}")
        
        stats = results.global_statistics
        print(f"\nAverage vulnerabilities per repository: {stats['average_vulnerabilities_per_repo']:.2f}")
        print(f"Average vulnerabilities per file: {stats['average_vulnerabilities_per_file']:.2f}")
        
        print(f"\nSeverity distribution:")
        for severity, count in stats['severity_distribution'].items():
            print(f"  {severity.upper()}: {count}")
        
        print(f"\nVulnerability types:")
        for vuln_type, count in sorted(
            stats['vulnerability_types'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]:  # Top 10
            print(f"  {vuln_type}: {count}")
        
        print(f"\nRepositories with source-to-sink flows: {stats['repositories_with_source_to_sink_flows']}")
        
        print(f"\nTop 10 unique vulnerability patterns:")
        for i, pattern in enumerate(results.unique_vulnerability_patterns[:10], 1):
            print(f"\n{i}. {pattern['type']} (occurs {pattern['occurrence_count']} times)")
            print(f"   Severity: {pattern['severity'].upper()}")
            print(f"   Pattern: {pattern['message_pattern'][:100]}...")
        
        print("\n" + "="*80)
        
        # Top repositories by vulnerability count
        top_repos = sorted(
            results.repositories,
            key=lambda r: r.total_vulnerabilities,
            reverse=True
        )[:5]
        
        if top_repos:
            print("\nTop 5 repositories by vulnerability count:")
            for i, repo in enumerate(top_repos, 1):
                print(f"{i}. {repo.repository}: {repo.total_vulnerabilities} vulnerabilities")

