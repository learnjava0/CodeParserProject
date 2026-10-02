import sys
from src.agent.parser.ast_parser import extract_functions
from src.agent.scanners.llm_scanner import scan_function
from src.agent.patcher.patch_validator import validate_patch

def analyze_file(filepath: str):
    """
    Core pipeline demonstrating the full agent flow on a single file:
    Parse AST -> Scan with LLM -> Validate Proposed Fixes
    """
    print(f"Analyzing {filepath}...")
    try:
        with open(filepath, 'rb') as f:
            source = f.read()
    except FileNotFoundError:
        print(f"File {filepath} not found.")
        return

    # Step 1: AST Extraction
    functions = extract_functions(source)
    print(f"Found {len(functions)} functions.")

    for func in functions:
        print(f"\nScanning function: {func['name']} (Lines {func['start_line']}-{func['end_line']})")
        
        # Step 5: LLM Scan (with masking)
        finding = scan_function(func['code'])
        
        if finding:
            print(f"[!] Vulnerability found: {finding.vuln_type} ({finding.severity} severity)")
            print(f"Explanation: {finding.explanation}")
            
            # Step 6: Patch Validation
            if finding.suggested_fix:
                print("Validating proposed patch...")
                is_valid = validate_patch(finding.suggested_fix)
                if is_valid:
                    print("[✓] Patch validated successfully! (0 syntax errors, 0 security findings)")
                else:
                    print("[x] Patch validation failed. Rejecting fix.")
        else:
            print("[✓] Function appears secure.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        analyze_file(sys.argv[1])
    else:
        print("Usage: python -m src.agent.main <filepath>")
