import argparse
import json
import os
import sys
from pathlib import Path

# Support running as an installed module (preferred) and as a direct script.
try:
    from .analyzer import DependencyAnalyzer
    from .mcdc import analyze_repo_mcdc
except ImportError:
    # Direct execution (e.g. `python CW_Test_Analyzer/ai_c_test_analyzer/cli.py ...`)
    # has no package context, so relative imports fail.
    this_file = Path(__file__).resolve()
    pkg_parent = this_file.parents[1]  # .../CW_Test_Analyzer
    if str(pkg_parent) not in sys.path:
        sys.path.insert(0, str(pkg_parent))
    from ai_c_test_analyzer.analyzer import DependencyAnalyzer
    from ai_c_test_analyzer.mcdc import analyze_repo_mcdc

from .safety_policy import SafetyPolicy, save_safety_summary

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
    parser.add_argument('--mcdc', action='store_true', help='Generate MC/DC gap analysis report (tests/analysis/mcdc_gaps.json)')
    parser.add_argument(
        '--safety-level',
        choices=list(SafetyPolicy.allowed_levels()),
        default='QM',
        help=(
            'Configures which analyses, test types, and review gates are required so generated tests align with SIL expectations '
            'without claiming certification.'
        ),
    )
    parser.add_argument('--policy-file', default=None)
    parser.add_argument('--disable-mcdc', action='store_true')
    
    args = parser.parse_args()
    
    if args.verbose:
        print(f"Repository path: {args.repo_path}")
    
    repo_path = Path(args.repo_path)
    if not repo_path.exists():
        print(f"Error: Repository path '{repo_path}' does not exist.")
        sys.exit(1)
    
    policy = SafetyPolicy.load(
        safety_level=args.safety_level,
        repo_root=repo_path,
        policy_file=args.policy_file,
        disable_mcdc=bool(args.disable_mcdc),
    )

    # Enforce mandatory analysis per safety level.
    want_mcdc = bool(args.mcdc) or policy.mcdc_analysis_required()
    if args.disable_mcdc:
        want_mcdc = False

    analyze_repo(repo_path, args.verbose, args.no_excel_output, mcdc=want_mcdc)

    # Best-effort: update safety summary.
    try:
        update: dict[str, object] = {
            'safety_level': policy.safety_level,
            'mcdc_analysis_performed': bool(want_mcdc),
        }
        if want_mcdc:
            gaps_path = repo_path / 'tests' / 'analysis' / 'mcdc_gaps.json'
            gaps_remaining = 0
            if gaps_path.exists():
                try:
                    gaps = json.loads(gaps_path.read_text(encoding='utf-8')) or {}
                    for _, decisions in (gaps.get('files', {}) or {}).items():
                        if isinstance(decisions, list):
                            gaps_remaining += len(decisions)
                except Exception:
                    gaps_remaining = 0
            update['mcdc_gaps_remaining'] = gaps_remaining
            update['coverage_status'] = {'mcdc': 'INCOMPLETE' if gaps_remaining else 'PASS'}

        save_safety_summary(repo_path, update)
    except Exception:
        pass
    
    if args.wait_before_exit:
        input("Press Enter to exit...")

def analyze_repo(repo_path, verbose=False, no_excel_output=False, mcdc: bool = False):
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

    if mcdc:
        mcdc_out = output_dir / 'mcdc_gaps.json'
        payload = analyze_repo_mcdc(repo_path)
        mcdc_out.write_text(json.dumps(payload, indent=2) + "\n", encoding='utf-8')
        if verbose:
            print(f"MC/DC gaps saved to {mcdc_out}")
    
    if verbose:
        print(f"Analysis saved to {output_file}")
        if not no_excel_output:
            print(f"Excel export saved to {excel_file}")

if __name__ == "__main__":
    main()