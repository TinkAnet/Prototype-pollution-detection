"""
Command-line interface for the Prototype Pollution Detection Tool.
"""

import argparse
import sys
from pathlib import Path
from typing import Optional

from .detector import PrototypePollutionDetector


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
    )
    
    parser.add_argument(
        "path",
        type=str,
        help="Path to JavaScript file or directory to analyze",
    )
    
    parser.add_argument(
        "-o", "--output",
        type=str,
        help="Output file for results (default: stdout)",
        default=None,
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.1.0",
    )
    
    args = parser.parse_args(argv)
    
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
            detector.print_results(results)
        
        return 0
    
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
