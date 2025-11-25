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
    findings: List[Dict[str, Any]]
    total_findings: int
    finding_types: Dict[str, int]
    severity_counts: Dict[str, int]
    has_source_to_sink_flows: bool
    analysis_metadata: Dict[str, Any]


@dataclass
class BatchAnalysisResult:
    """Results of batch analysis across multiple repositories."""
    total_repositories: int
    total_files: int
    total_findings: int
    repositories: List[RepositoryAnalysis]
    global_statistics: Dict[str, Any]
    unique_finding_patterns: List[Dict[str, Any]]


class BatchAnalyzer:
    """
    Batch analyzer for crawled code sources.
    
    Features:
    - Groups files by repository for cross-file analysis
    - Deduplicates findings across repositories
    - Aggregates statistics
    - Identifies unique finding patterns
    """
    
    def __init__(self, verbose: bool = False, path_manager=None):
        """
        Initialize the batch analyzer.
        
        Args:
            verbose: Enable verbose output
            path_manager: PathManager instance. If None, creates a new one.
        """
        self.verbose = verbose
        self.detector = PrototypePollutionDetector(verbose=verbose)
        
        # Use PathManager for organized directory structure
        if path_manager is None:
            from .paths import get_path_manager
            path_manager = get_path_manager()
        
        self.path_manager = path_manager
        
        # Deduplication tracking
        self._finding_signatures: Set[str] = set()
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
        all_findings = []
        
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
                all_findings.extend(repo_result.findings)
        
        # Step 3: Aggregate statistics
        global_stats = self._compute_global_statistics(repository_results)
        
        # Step 4: Identify unique finding patterns
        unique_patterns = self._identify_unique_patterns(all_findings)
        
        return BatchAnalysisResult(
            total_repositories=len(repository_results),
            total_files=sum(len(r.files) for r in repository_results),
            total_findings=len(all_findings),
            repositories=repository_results,
            global_statistics=global_stats,
            unique_finding_patterns=unique_patterns,
        )
    
    def _group_files_by_repository(self, sources_dir: Path) -> Dict[str, List[Path]]:
        """
        Group files by repository name.
        
        Handles two directory structures:
        1. Full structure with owner/repo:
           crawler_sources/
             owner1/
               repo1/
                 file1.js
        2. Single repository directory:
           repo_dir/
             file1.js
        
        Returns:
            Dictionary mapping repo_name -> list of file paths
        """
        repo_files = defaultdict(list)
        
        if not sources_dir.exists():
            return repo_files
        
        # Check if this is a single repository directory (contains files directly or has files in subdirs)
        # First, check if there are any JS/HTML files directly in this directory
        has_files_here = False
        for pattern in ["*.js", "*.jsx", "*.mjs", "*.cjs", "*.html", "*.htm", "*.ts", "*.tsx"]:
            if list(sources_dir.glob(pattern)):
                has_files_here = True
                break
        
        # If files are here, treat this as a single repository
        if has_files_here:
            repo_name = sources_dir.name
            # If parent is an owner directory, use owner/repo format
            if sources_dir.parent.name and sources_dir.parent.parent.exists():
                # Check if parent looks like an owner directory (has other repo dirs)
                parent_has_repos = any(d.is_dir() for d in sources_dir.parent.iterdir())
                if parent_has_repos:
                    repo_name = f"{sources_dir.parent.name}/{sources_dir.name}"
            
            for pattern in ["**/*.js", "**/*.jsx", "**/*.mjs", "**/*.cjs", 
                           "**/*.html", "**/*.htm", "**/*.ts", "**/*.tsx"]:
                for file_path in sources_dir.glob(pattern):
                    if file_path.is_file():
                        repo_files[repo_name].append(file_path)
            
            return dict(repo_files)
        
        # Otherwise, traverse owner/repo structure
        for owner_dir in sources_dir.iterdir():
            if not owner_dir.is_dir():
                continue
            
            # Check if owner_dir contains repo directories or files directly
            subdirs = [d for d in owner_dir.iterdir() if d.is_dir()]
            has_files = any(f.is_file() for f in owner_dir.iterdir())
            
            if subdirs:
                # Standard owner/repo structure
                for repo_dir in subdirs:
                    # Repository name: owner/repo
                    repo_name = f"{owner_dir.name}/{repo_dir.name}"
                    
                    # Find all JavaScript/HTML files
                    for pattern in ["**/*.js", "**/*.jsx", "**/*.mjs", "**/*.cjs", 
                                   "**/*.html", "**/*.htm", "**/*.ts", "**/*.tsx"]:
                        for file_path in repo_dir.glob(pattern):
                            if file_path.is_file():
                                repo_files[repo_name].append(file_path)
            elif has_files:
                # Owner directory contains files directly (treat as repo)
                repo_name = owner_dir.name
                for pattern in ["**/*.js", "**/*.jsx", "**/*.mjs", "**/*.cjs", 
                               "**/*.html", "**/*.htm", "**/*.ts", "**/*.tsx"]:
                    for file_path in owner_dir.glob(pattern):
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
                
                # Extract findings
                findings = []
                for file_result in analysis_result.get("files", []):
                    file_findings = file_result.get("findings", [])
                    for finding in file_findings:
                        # Map back to original file path
                        temp_file = file_result.get("file", "")
                        original_file = self._map_to_original_path(temp_file, file_paths)
                        
                        finding_dict = {
                            "severity": finding.get("severity"),
                            "line": finding.get("line"),
                            "column": finding.get("column"),
                            "message": finding.get("message"),
                            "code_snippet": finding.get("code_snippet", "")[:200],  # Limit size
                            "type": finding.get("type"),
                            "file": original_file,
                        }
                        
                        # Deduplicate by signature
                        signature = self._finding_signature(finding_dict)
                        if signature not in self._finding_signatures:
                            self._finding_signatures.add(signature)
                            findings.append(finding_dict)
                
                # Compute statistics
                finding_types = defaultdict(int)
                severity_counts = defaultdict(int)
                has_source_to_sink = False
                
                for finding in findings:
                    finding_type = finding.get("type", "unknown")
                    severity = finding.get("severity", "low")
                    finding_types[finding_type] += 1
                    severity_counts[severity] += 1
                    
                    if "source_to_sink" in finding_type.lower():
                        has_source_to_sink = True
                
                return RepositoryAnalysis(
                    repository=repo_name,
                    files=[str(f) for f in file_paths],
                    findings=findings,
                    total_findings=len(findings),
                    finding_types=dict(finding_types),
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
            finding.get("type", ""),
            finding.get("message", "")[:100],  # First 100 chars
            finding.get("file", ""),
            finding.get("line", 0),
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
        total_findings = sum(r.total_findings for r in repository_results)
        total_files = sum(len(r.files) for r in repository_results)
        
        # Aggregate finding types
        type_counts = defaultdict(int)
        severity_counts = defaultdict(int)
        repos_with_source_to_sink = 0
        
        for repo_result in repository_results:
            for finding_type, count in repo_result.finding_types.items():
                type_counts[finding_type] += count
            
            for severity, count in repo_result.severity_counts.items():
                severity_counts[severity] += count
            
            if repo_result.has_source_to_sink_flows:
                repos_with_source_to_sink += 1
        
        return {
            "total_findings": total_findings,
            "total_files": total_files,
            "average_findings_per_repo": (
                total_findings / len(repository_results) if repository_results else 0
            ),
            "average_findings_per_file": (
                total_findings / total_files if total_files > 0 else 0
            ),
            "finding_types": dict(type_counts),
            "severity_distribution": dict(severity_counts),
            "repositories_with_source_to_sink_flows": repos_with_source_to_sink,
            "repositories_with_findings": len([
                r for r in repository_results if r.total_findings > 0
            ]),
        }
    
    def _identify_unique_patterns(
        self,
        findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Identify unique finding patterns across repositories.
        
        Args:
            findings: List of all findings
            
        Returns:
            List of unique patterns with occurrence counts
        """
        # Group by vulnerability type and message pattern
        pattern_groups = defaultdict(list)
        
        for finding in findings:
            # Create pattern key from type and message
            pattern_key = (
                finding.get("type", "unknown"),
                finding.get("message", "")[:150],  # First 150 chars
            )
            pattern_groups[pattern_key].append(finding)
        
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
        output_path: Optional[Path] = None,
        format: str = "json",
    ) -> Path:
        """
        Save batch analysis results to organized directory structure.
        
        Args:
            results: BatchAnalysisResult object
            output_path: Optional output path. If None, uses organized structure.
            format: Output format ("json" or "jsonl")
            
        Returns:
            Path to the saved results file
        """
        if output_path is None:
            # Use organized structure
            result_dir = self.path_manager.get_batch_result_dir()
            
            # Save summary.json - high-level statistics only (no full finding lists)
            summary_file = result_dir / "summary.json"
            summary_data = {
                "total_repositories": results.total_repositories,
                "total_files": results.total_files,
                "total_findings": results.total_findings,
                "global_statistics": results.global_statistics,
                "unique_finding_patterns": results.unique_finding_patterns,
                "repositories_summary": [
                    {
                        "repository": r.repository,
                        "file_count": len(r.files),
                        "finding_count": r.total_findings,
                        "finding_types": r.finding_types,
                        "severity_counts": r.severity_counts,
                        "has_source_to_sink_flows": r.has_source_to_sink_flows,
                    }
                    for r in results.repositories
                ],
            }
            with open(summary_file, 'w', encoding='utf-8') as f:
                json.dump(summary_data, f, indent=2, ensure_ascii=False)
            
            # Save detailed.json - full results with all finding details
            detailed_file = result_dir / "detailed.json"
            with open(detailed_file, 'w', encoding='utf-8') as f:
                json.dump(asdict(results), f, indent=2, ensure_ascii=False)
            
            # Save repositories.jsonl - one repository per line (JSONL format for easier processing)
            repos_file = result_dir / "repositories.jsonl"
            with open(repos_file, 'w', encoding='utf-8') as f:
                for repo in results.repositories:
                    f.write(json.dumps(asdict(repo), ensure_ascii=False) + '\n')
            
            # Create symlink to latest
            self.path_manager.create_latest_symlink(result_dir, "latest")
            
            if self.verbose:
                print(f"Results saved to {summary_file}")
            
            return summary_file
        
        # Custom output path specified - save summary format there
        if format == "json":
            # Save summary format (without full finding lists)
            summary_data = {
                "total_repositories": results.total_repositories,
                "total_files": results.total_files,
                "total_findings": results.total_findings,
                "global_statistics": results.global_statistics,
                "unique_finding_patterns": results.unique_finding_patterns,
                "repositories_summary": [
                    {
                        "repository": r.repository,
                        "file_count": len(r.files),
                        "finding_count": r.total_findings,
                        "finding_types": r.finding_types,
                        "severity_counts": r.severity_counts,
                        "has_source_to_sink_flows": r.has_source_to_sink_flows,
                    }
                    for r in results.repositories
                ],
            }
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(summary_data, f, indent=2, ensure_ascii=False)
        elif format == "jsonl":
            # Save as JSONL (one repository per line)
            with open(output_path, 'w', encoding='utf-8') as f:
                for repo in results.repositories:
                    f.write(json.dumps(asdict(repo), ensure_ascii=False) + '\n')
        
        if self.verbose:
            print(f"Results saved to {output_path}")
        
        return output_path
    
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
        print(f"Total findings: {results.total_findings}")
        
        stats = results.global_statistics
        print(f"\nAverage findings per repository: {stats['average_findings_per_repo']:.2f}")
        print(f"Average findings per file: {stats['average_findings_per_file']:.2f}")
        
        print(f"\nSeverity distribution:")
        for severity, count in stats['severity_distribution'].items():
            print(f"  {severity.upper()}: {count}")
        
        print(f"\nFinding types:")
        for finding_type, count in sorted(
            stats['finding_types'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]:  # Top 10
            print(f"  {finding_type}: {count}")
        
        print(f"\nRepositories with source-to-sink flows: {stats['repositories_with_source_to_sink_flows']}")
        
        print(f"\nTop 10 unique finding patterns:")
        for i, pattern in enumerate(results.unique_finding_patterns[:10], 1):
            print(f"\n{i}. {pattern['type']} (occurs {pattern['occurrence_count']} times)")
            print(f"   Severity: {pattern['severity'].upper()}")
            print(f"   Pattern: {pattern['message_pattern'][:100]}...")
        
        print("\n" + "="*80)
        
        # Top repositories by finding count
        top_repos = sorted(
            results.repositories,
            key=lambda r: r.total_findings,
            reverse=True
        )[:5]
        
        if top_repos:
            print("\nTop 5 repositories by finding count:")
            for i, repo in enumerate(top_repos, 1):
                print(f"{i}. {repo.repository}: {repo.total_findings} findings")

