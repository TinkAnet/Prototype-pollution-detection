"""
Orchestrator for GitHub crawling and analysis workflow.

This module coordinates the GitHub crawler, LLM analyzer, and detector
to find and analyze prototype pollution vulnerabilities.
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import asdict

from .github_crawler import GitHubCrawler, CodeSnippet
from .llm_analyzer import LLMAnalyzer
from .detector import PrototypePollutionDetector
from .analysis import Vulnerability
from .batch_analyzer import BatchAnalyzer


class CrawlerOrchestrator:
    """
    Orchestrates the complete workflow of crawling GitHub and analyzing results.
    
    Workflow:
    1. Search GitHub for potentially vulnerable code
    2. Filter results using LLM (optional)
    3. Analyze code snippets with detector
    4. Generate comprehensive report
    """
    
    def __init__(self, verbose: bool = False, path_manager=None):
        """
        Initialize the orchestrator.
        
        Args:
            verbose: Enable verbose output
            path_manager: PathManager instance. If None, creates a new one.
        """
        self.verbose = verbose
        
        # Use PathManager for organized directory structure
        if path_manager is None:
            from .paths import get_path_manager
            path_manager = get_path_manager()
        
        self.path_manager = path_manager
        self.github_crawler = GitHubCrawler(verbose=verbose, path_manager=path_manager)
        self.llm_analyzer = LLMAnalyzer(verbose=verbose)
        self.detector = PrototypePollutionDetector(verbose=verbose)
        self.batch_analyzer = BatchAnalyzer(verbose=verbose)
    
    def crawl_and_analyze(
        self,
        max_results: int = 50,
        use_llm_filter: bool = True,
        languages: List[str] = None,
        min_stars: int = 0,
        skip_analysis: bool = False,
    ) -> Dict[str, Any]:
        """
        Crawl GitHub and analyze results for prototype pollution vulnerabilities.
        
        Args:
            max_results: Maximum number of code snippets to analyze
            use_llm_filter: Whether to use LLM to filter results
            languages: List of languages to search
            min_stars: Minimum repository stars
            
        Returns:
            Dictionary containing analysis results
        """
        if self.verbose:
            print("Starting GitHub crawl and analysis...")
        
        # Step 1: Search GitHub
        print(f"Step 1: Searching GitHub for vulnerable code patterns...")
        
        snippets = self.github_crawler.search_vulnerable_code(
            max_results=max_results * 2,  # Get more to filter
            languages=languages,
            min_stars=min_stars
        )
        
        print(f"Found {len(snippets)} potential code snippets from GitHub")
        
        if len(snippets) == 0:
            print("Warning: No code snippets found. This could be due to:")
            print("  - GitHub API rate limits")
            print("  - Search patterns not matching any code")
            print("  - Network connectivity issues")
            print("Try running with --verbose to see detailed search progress")
        
        # Step 2: Filter with LLM (optional)
        if use_llm_filter and self.llm_analyzer.is_available():
            if self.verbose:
                print("Step 2: Filtering results with LLM...")
            
            snippet_dicts = [
                {
                    "code": snippet.code,
                    "file_path": snippet.file_path,
                    "repository": snippet.repository,
                    "url": snippet.url,
                }
                for snippet in snippets
            ]
            
            filtered = self.llm_analyzer.filter_vulnerable_snippets(
                snippet_dicts,
                max_analyze=min(max_results, len(snippet_dicts))
            )
            
            # Reconstruct snippets from filtered results
            filtered_snippets = []
            for item in filtered:
                # Find original snippet
                for snippet in snippets:
                    if snippet.url == item.get("url"):
                        filtered_snippets.append(snippet)
                        break
            
            snippets = filtered_snippets[:max_results]
            
            if self.verbose:
                print(f"LLM filtered to {len(snippets)} high-confidence snippets")
        else:
            snippets = snippets[:max_results]
        
        # Step 3: Analyze with detector
        if skip_analysis:
            if self.verbose:
                print("Step 3: Analyzing code snippets with detector... (skipped)")
        else:
            if self.verbose:
                print("Step 3: Analyzing code snippets with detector...")

        results = {
            "total_snippets": len(snippets),
            "analyzed_snippets": [],
            "total_vulnerabilities": 0,
            "vulnerabilities_by_type": {},
            "vulnerabilities_by_severity": {
                "high": 0,
                "medium": 0,
                "low": 0,
            },
        }

        for snippet in snippets:
            if skip_analysis:
                snippet_result = {
                    "repository": snippet.repository,
                    "file_path": snippet.file_path,
                    "url": snippet.url,
                    "language": snippet.language,
                    "stars": snippet.stars,
                    "vulnerabilities": [],
                    "vulnerability_count": 0,
                    "analysis_skipped": True,
                }
            else:
                snippet_result = self._analyze_snippet(snippet)
                vuln_count = len(snippet_result.get("vulnerabilities", []))
                results["total_vulnerabilities"] += vuln_count
                for vuln in snippet_result.get("vulnerabilities", []):
                    vuln_type = vuln.get("type", "unknown")
                    severity = vuln.get("severity", "low")
                    results["vulnerabilities_by_type"][vuln_type] = \
                        results["vulnerabilities_by_type"].get(vuln_type, 0) + 1
                    results["vulnerabilities_by_severity"][severity] += 1

            results["analyzed_snippets"].append(snippet_result)
        
        # Step 4: Generate summary with LLM (optional)
        if not skip_analysis and self.llm_analyzer.is_available():
            if self.verbose:
                print("Step 4: Generating summary with LLM...")
            
            findings = []
            for snippet_result in results["analyzed_snippets"]:
                for vuln in snippet_result.get("vulnerabilities", []):
                    findings.append({
                        "repository": snippet_result["repository"],
                        "file": snippet_result["file_path"],
                        "type": vuln.get("type"),
                        "severity": vuln.get("severity"),
                        "message": vuln.get("message"),
                    })
            
            summary = self.llm_analyzer.summarize_findings(findings)
            if summary:
                results["llm_summary"] = summary
        
        return results
    
    def _analyze_snippet(self, snippet: CodeSnippet) -> Dict[str, Any]:
        """
        Analyze a single code snippet.
        
        Args:
            snippet: CodeSnippet to analyze
            
        Returns:
            Analysis result dictionary
        """
        # Create a temporary file for analysis
        import tempfile
        
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.js',
            delete=False,
            encoding='utf-8'
        ) as f:
            f.write(snippet.code)
            temp_path = Path(f.name)
        
        try:
            # Analyze with detector
            analysis_result = self.detector.analyze(temp_path)
            
            # Enhance with snippet metadata
            result = {
                "repository": snippet.repository,
                "file_path": snippet.file_path,
                "url": snippet.url,
                "language": snippet.language,
                "stars": snippet.stars,
                "vulnerabilities": analysis_result.get("vulnerabilities", []),
                "vulnerability_count": analysis_result.get("vulnerability_count", 0),
            }
            
            # Add LLM analysis if available
            if self.llm_analyzer.is_available():
                llm_result = self.llm_analyzer.analyze_code_snippet(
                    snippet.code,
                    context=f"{snippet.repository}/{snippet.file_path}",
                    language=snippet.language
                )
                
                if llm_result:
                    result["llm_analysis"] = {
                        "is_vulnerable": llm_result.is_vulnerable,
                        "confidence": llm_result.confidence,
                        "explanation": llm_result.explanation,
                    }
            
            return result
        
        finally:
            # Clean up temp file
            if temp_path.exists():
                temp_path.unlink()
    
    def search_repository(
        self,
        repo_name: str,
        use_llm_filter: bool = True,
        skip_analysis: bool = False,
    ) -> Dict[str, Any]:
        """
        Search and analyze a specific repository.
        
        Args:
            repo_name: Repository name (owner/repo)
            use_llm_filter: Whether to use LLM filtering
            
        Returns:
            Analysis results dictionary
        """
        if self.verbose:
            print(f"Searching repository: {repo_name}")
        
        snippets = self.github_crawler.search_repository(repo_name)
        
        if self.verbose:
            print(f"Found {len(snippets)} code snippets")
        
        results = {
            "repository": repo_name,
            "total_snippets": len(snippets),
            "analyzed_snippets": [],
            "total_vulnerabilities": 0,
        }
        
        for snippet in snippets:
            if skip_analysis:
                snippet_result = {
                    "repository": snippet.repository,
                    "file_path": snippet.file_path,
                    "url": snippet.url,
                    "language": snippet.language,
                    "stars": snippet.stars,
                    "vulnerabilities": [],
                    "vulnerability_count": 0,
                    "analysis_skipped": True,
                }
            else:
                snippet_result = self._analyze_snippet(snippet)
                results["total_vulnerabilities"] += snippet_result.get("vulnerability_count", 0)

            results["analyzed_snippets"].append(snippet_result)
        
        return results
    
    def analyze_crawled_sources(
        self,
        sources_dir: Path,
        max_files_per_repo: Optional[int] = None,
        output_file: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """
        Analyze already-crawled code sources using batch analyzer.
        
        This method is optimized for analyzing the crawler_sources directory,
        providing better cross-file analysis and deduplication.
        
        Args:
            sources_dir: Directory containing crawled sources
            max_files_per_repo: Maximum files to analyze per repository
            output_file: Optional output file path for results
            
        Returns:
            Dictionary containing batch analysis results
        """
        if self.verbose:
            print(f"Analyzing crawled sources in: {sources_dir}")
        
        # Use batch analyzer for optimized analysis
        batch_results = self.batch_analyzer.analyze_crawler_sources(
            sources_dir=sources_dir,
            max_files_per_repo=max_files_per_repo,
        )
        
        # Convert to dictionary format
        results = {
            "total_repositories": batch_results.total_repositories,
            "total_files": batch_results.total_files,
            "total_vulnerabilities": batch_results.total_vulnerabilities,
            "repositories": [
                {
                    "repository": r.repository,
                    "files": r.files,
                    "vulnerabilities": r.vulnerabilities,
                    "total_vulnerabilities": r.total_vulnerabilities,
                    "vulnerability_types": r.vulnerability_types,
                    "severity_counts": r.severity_counts,
                    "has_source_to_sink_flows": r.has_source_to_sink_flows,
                    "analysis_metadata": r.analysis_metadata,
                }
                for r in batch_results.repositories
            ],
            "global_statistics": batch_results.global_statistics,
            "unique_vulnerability_patterns": batch_results.unique_vulnerability_patterns,
        }
        
        # Save results (uses organized structure if output_file is None)
        saved_path = self.batch_analyzer.save_results(batch_results, output_file)
        
        if output_file is None and self.verbose:
            print(f"\nResults saved to organized structure: {saved_path.parent}")
        
        # Print summary
        if self.verbose:
            self.batch_analyzer.print_summary(batch_results)
        
        return results
    
    def save_results(self, results: Dict[str, Any], output_file: Path) -> None:
        """
        Save analysis results to a JSON file.
        
        Args:
            results: Analysis results dictionary
            output_file: Output file path
        """
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        if self.verbose:
            print(f"Results saved to {output_file}")
    
    def print_results(self, results: Dict[str, Any]) -> None:
        """
        Print analysis results in a human-readable format.
        
        Args:
            results: Analysis results dictionary
        """
        print("\n" + "="*80)
        print("GitHub Crawl Analysis Results")
        print("="*80)
        
        print(f"\nTotal snippets analyzed: {results.get('total_snippets', 0)}")
        print(f"Total vulnerabilities found: {results.get('total_vulnerabilities', 0)}")
        
        severity = results.get('vulnerabilities_by_severity', {})
        print(f"\nBy Severity:")
        print(f"  High:   {severity.get('high', 0)}")
        print(f"  Medium: {severity.get('medium', 0)}")
        print(f"  Low:    {severity.get('low', 0)}")
        
        vuln_types = results.get('vulnerabilities_by_type', {})
        if vuln_types:
            print(f"\nBy Type:")
            for vuln_type, count in sorted(vuln_types.items(), key=lambda x: x[1], reverse=True):
                print(f"  {vuln_type}: {count}")
        
        # Print LLM summary if available
        if 'llm_summary' in results:
            print(f"\n{'='*80}")
            print("LLM Analysis Summary:")
            print("="*80)
            print(results['llm_summary'])
        
        # Print top vulnerabilities
        print(f"\n{'='*80}")
        print("Top Vulnerabilities:")
        print("="*80)
        
        top_vulns = []
        for snippet_result in results.get('analyzed_snippets', []):
            for vuln in snippet_result.get('vulnerabilities', []):
                top_vulns.append({
                    'repository': snippet_result['repository'],
                    'file': snippet_result['file_path'],
                    'severity': vuln.get('severity', 'low'),
                    'type': vuln.get('type', 'unknown'),
                    'message': vuln.get('message', ''),
                    'url': snippet_result.get('url', ''),
                })
        
        # Sort by severity
        severity_order = {'high': 3, 'medium': 2, 'low': 1}
        top_vulns.sort(key=lambda x: severity_order.get(x['severity'], 0), reverse=True)
        
        for i, vuln in enumerate(top_vulns[:10], 1):
            print(f"\n{i}. [{vuln['severity'].upper()}] {vuln['repository']}/{vuln['file']}")
            print(f"   Type: {vuln['type']}")
            print(f"   {vuln['message'][:100]}...")
            print(f"   URL: {vuln['url']}")
