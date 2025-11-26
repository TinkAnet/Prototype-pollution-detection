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


def main(argv: Optional[list] = None) -> int:
    """
    Main entry point for the CLI.
    
    Args:
        argv: Command-line arguments (defaults to sys.argv)
        
    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    parser = argparse.ArgumentParser(
        prog="prototype-pollution-detector",
        description="Detect client-side prototype pollution vulnerabilities in JavaScript code",
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
        "-d", "--dynamic",
        action="store_true",
        help="Enable dynamic verification (executes code)",
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
        results = detector.analyze(input_path, dynamic_verify=args.dynamic)
        
        # Output results
        if args.output:
            output_path = Path(args.output)
            detector.save_results(results, output_path)
            print(f"Results saved to {args.output}")
        else:
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
    if not args.output:
        print("Error: --output is required for crawl command", file=sys.stderr)
        return 1
    
    # Create orchestrator
    orchestrator = CrawlerOrchestrator(verbose=args.verbose)
    
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
            
            results = orchestrator.crawl_and_analyze(
                max_results=args.max_results,
                use_llm_filter=not args.no_llm,
                languages=args.languages,
                min_stars=args.min_stars,
                skip_analysis=args.skip_analysis,
            )
        
        # Save results
        output_path = Path(args.output)
        orchestrator.save_results(results, output_path)
        
        # Print summary
        orchestrator.print_results(results)
        
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
