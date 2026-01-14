import argparse
import json
import os
import sys
from pathlib import Path

from .analyzer import DependencyAnalyzer

def validate_environment():
    """Validate that required tools and dependencies are available."""
    # Check for Python version
    if sys.version_info < (3, 8):
        print("Error: Python 3.8 or higher is required.")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="AI C Test Analyzer")
    parser.add_argument('--repo-path', required=True, help='Path to the repository')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--wait-before-exit', action='store_true', help='Wait for user input before exiting')
    parser.add_argument('--no-excel-output', action='store_true', help='Disable Excel output')
    
    args = parser.parse_args()
    
    if args.verbose:
        print(f"Repository path: {args.repo_path}")
    
    repo_path = Path(args.repo_path)
    if not repo_path.exists():
        print(f"Error: Repository path '{repo_path}' does not exist.")
        sys.exit(1)
    
    analyze_repo(repo_path, args.verbose, args.no_excel_output)
    
    if args.wait_before_exit:
        input("Press Enter to exit...")

def analyze_repo(repo_path, verbose=False, no_excel_output=False):
    """Analyze all C/C++ files in the repository."""
    analyzer = DependencyAnalyzer(str(repo_path))
    scan_results = analyzer.perform_repo_scan()
    
    output_dir = repo_path / 'tests' / 'analysis'
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Save detailed results
    analyzer.save_repo_scan_results(scan_results, str(output_dir))
    
    # Save JSON summary
    output_file = output_dir / 'analysis.json'
    with open(output_file, 'w') as f:
        json.dump(scan_results, f, indent=2)
    
    # Export to Excel if not disabled
    if not no_excel_output:
        excel_file = output_dir / 'analysis.xlsx'
        analyzer.export_to_excel(scan_results, str(excel_file))
    
    if verbose:
        print(f"Analysis saved to {output_file}")
        if not no_excel_output:
            print(f"Excel export saved to {excel_file}")

if __name__ == "__main__":
    main()