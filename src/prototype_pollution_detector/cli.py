"""
Command-line interface for the Prototype Pollution Detection Tool.
"""

import argparse
import sys
from pathlib import Path
from typing import Optional

from .detector import PrototypePollutionDetector
from .crawler_orchestrator import CrawlerOrchestrator
from .config import config
from .paths import get_path_manager


def main(argv: Optional[list] = None) -> int:
    """
    Main entry point for the CLI.
    
    Args:
        argv: Command-line arguments (defaults to sys.argv)
        
    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    parser = argparse.ArgumentParser(
        prog="pollutaint",
        description="Taint analysis tool for detecting prototype pollution vulnerabilities in JavaScript code",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze local files
  %(prog)s analyze path/to/file.js
  %(prog)s analyze path/to/directory/ -o results.json
  
  # Crawl GitHub for vulnerabilities
  %(prog)s crawl --max-results 50 -o crawl_results.json
  %(prog)s crawl --repo owner/repo-name -o repo_results.json
        """,
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Analyze command
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze local JavaScript/HTML files for vulnerabilities"
    )
    analyze_parser.add_argument(
        "path",
        type=str,
        help="Path to JavaScript/HTML file or directory to analyze",
    )
    analyze_parser.add_argument(
        "-o", "--output",
        type=str,
        help="Output file for results (default: stdout)",
        default=None,
    )
    analyze_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    
    # Crawl command
    crawl_parser = subparsers.add_parser(
        "crawl",
        help="Crawl GitHub for potentially vulnerable code"
    )
    crawl_parser.add_argument(
        "--max-results",
        type=int,
        default=50,
        help="Maximum number of code snippets to analyze (default: 50)",
    )
    crawl_parser.add_argument(
        "--repo",
        type=str,
        help="Specific repository to search (format: owner/repo)",
        default=None,
    )
    crawl_parser.add_argument(
        "--languages",
        type=str,
        nargs="+",
        default=["javascript", "typescript"],
        help="Languages to search (default: javascript typescript)",
    )
    crawl_parser.add_argument(
        "--min-stars",
        type=int,
        default=0,
        help="Minimum repository stars (default: 0)",
    )
    crawl_parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Disable LLM filtering (faster but less accurate)",
    )
    crawl_parser.add_argument(
        "--skip-analysis",
        action="store_true",
        help="Skip static analysis step and only collect snippets",
    )
    crawl_parser.add_argument(
        "-o", "--output",
        type=str,
        help="Output file for results (required for crawl)",
        default=None,
    )
    crawl_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    
    # Batch analyze command
    batch_parser = subparsers.add_parser(
        "batch-analyze",
        help="Analyze already-crawled code sources with optimized batch processing"
    )
    batch_parser.add_argument(
        "sources_dir",
        type=str,
        help="Directory containing crawled sources (organized by repository)",
    )
    batch_parser.add_argument(
        "-o", "--output",
        type=str,
        help="Output file for results (default: batch_results.json)",
        default="batch_results.json",
    )
    batch_parser.add_argument(
        "--max-files-per-repo",
        type=int,
        help="Maximum files to analyze per repository (default: no limit)",
        default=None,
    )
    batch_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    
    # Global arguments
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.2.0",
    )
    
    args = parser.parse_args(argv)
    
    # Validate configuration
    if args.command == "crawl":
        validation = config.validate()
        if validation["warnings"]:
            for warning in validation["warnings"]:
                if "GITHUB_TOKEN" in warning:
                    print(f"Warning: {warning}", file=sys.stderr)
                    print("  GitHub code search requires authentication. Create a token at:", file=sys.stderr)
                    print("  https://github.com/settings/tokens", file=sys.stderr)
                else:
                    print(f"Info: {warning}", file=sys.stderr)
    
    # Execute command
    if args.command == "analyze":
        return handle_analyze(args)
    elif args.command == "crawl":
        return handle_crawl(args)
    elif args.command == "batch-analyze":
        return handle_batch_analyze(args)
    else:
        parser.print_help()
        return 1


def handle_analyze(args) -> int:
    """Handle the analyze command."""
    # Validate input path
    input_path = Path(args.path)
    if not input_path.exists():
        print(f"Error: Path '{args.path}' does not exist", file=sys.stderr)
        return 1
    
    # Create detector instance
    detector = PrototypePollutionDetector(verbose=args.verbose)
    
    try:
        # Analyze the provided path
        results = detector.analyze(input_path)
        
        # Output results
        if args.output:
            output_path = Path(args.output)
            detector.save_results(results, output_path)
            print(f"Results saved to {args.output}")
        else:
            # Use organized structure if no output specified
            path_manager = get_path_manager()
            input_name = input_path.name if input_path.is_file() else input_path.name
            output_path = path_manager.get_analyze_result_file(input_name)
            detector.save_results(results, output_path)
            print(f"Results saved to {output_path}")
        
        detector.print_results(results)
        
        return 0
    
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def handle_crawl(args) -> int:
    """Handle the crawl command."""
    # Create orchestrator
    path_manager = get_path_manager()
    orchestrator = CrawlerOrchestrator(verbose=args.verbose, path_manager=path_manager)
    
    try:
        if args.repo:
            # Search specific repository
            if args.verbose:
                print(f"Searching repository: {args.repo}")
            
            results = orchestrator.search_repository(
                args.repo,
                use_llm_filter=not args.no_llm,
                skip_analysis=args.skip_analysis,
            )
        else:
            # General GitHub search
            if args.verbose:
                print("Starting GitHub crawl...")
                print(f"Crawled sources will be saved to: {path_manager.get_crawl_sources_dir()}")
            
            results = orchestrator.crawl_and_analyze(
                max_results=args.max_results,
                use_llm_filter=not args.no_llm,
                languages=args.languages,
                min_stars=args.min_stars,
                skip_analysis=args.skip_analysis,
            )
        
        # Save results
        if args.output:
            output_path = Path(args.output)
        else:
            # Use organized structure
            output_path = None
        
        saved_path = orchestrator.save_results(results, output_path)
        
        # Print summary
        orchestrator.print_results(results)
        
        if args.verbose:
            print(f"\nCrawl session directory: {orchestrator.github_crawler.crawl_session_dir}")
            print(f"Results directory: {saved_path.parent}")
        
        return 0
    
    except KeyboardInterrupt:
        print("\nInterrupted by user", file=sys.stderr)
        return 130
    
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def handle_batch_analyze(args) -> int:
    """Handle the batch-analyze command."""
    # Validate input path
    sources_dir = Path(args.sources_dir)
    if not sources_dir.exists():
        print(f"Error: Sources directory '{args.sources_dir}' does not exist", file=sys.stderr)
        return 1
    
    if not sources_dir.is_dir():
        print(f"Error: '{args.sources_dir}' is not a directory", file=sys.stderr)
        return 1
    
    # Create orchestrator with path manager
    path_manager = get_path_manager()
    orchestrator = CrawlerOrchestrator(verbose=args.verbose, path_manager=path_manager)
    
    try:
        # Determine output file
        if args.output:
            output_file = Path(args.output)
        else:
            # Use organized structure
            output_file = None
        
        # Analyze crawled sources
        results = orchestrator.analyze_crawled_sources(
            sources_dir=sources_dir,
            max_files_per_repo=args.max_files_per_repo,
            output_file=output_file,
        )
        
        if args.output:
            print(f"\nBatch analysis complete. Results saved to {args.output}")
        else:
            result_dir = path_manager.get_batch_result_dir()
            print(f"\nBatch analysis complete. Results saved to {result_dir}")
            print(f"  - Summary: {result_dir / 'summary.json'}")
            print(f"  - Detailed: {result_dir / 'detailed.json'}")
            print(f"  - Repositories: {result_dir / 'repositories.json'}")
        
        return 0
    
    except KeyboardInterrupt:
        print("\nInterrupted by user", file=sys.stderr)
        return 130
    
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
