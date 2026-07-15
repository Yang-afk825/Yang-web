# -*- coding: utf-8 -*-
"""
CTF+ Batch Solver — 读取 CTF+ 题目 JSON，分类并批量求解

Usage:
    python ctfplus_batch_solver.py [--dry-run] [--category web|crypto|reverse|...]
"""
import sys, os, json

sys.path.insert(0, r'C:\Users\阳\.qclaw\workspace\Yang-web\yang_web')
from core.smart_solver import SmartSolver, classify_problem

CTFPLUS_JSON = r'C:\Users\阳\.qclaw\workspace\ctfplus_problems_detailed.json'

def load_problems(filepath: str = CTFPLUS_JSON) -> list:
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)

def print_header():
    print("=" * 70)
    print("  CTF+ Batch Solver — Yang-Web Smart Solver v2.1")
    print("=" * 70)

def analyze_problems(problems: list):
    """分析题目分布，不实际求解."""
    solver = SmartSolver()
    
    print("\n--- Problem Classification ---")
    print("-" * 70)
    
    cats = {}
    for p in problems:
        cat = classify_problem(p)
        cats[cat] = cats.get(cat, 0) + 1
        
        docker = "[Docker]" if p.get("supportsDynamicContainer") else "[Static]"
        has_attach = "[File]" if p.get("attachments") else "     "
        print(f"  [{cat:<12}] {p['name'][:40]:<42} {docker} {has_attach}")
    
    print("\n--- Category Distribution ---")
    for cat, count in sorted(cats.items()):
        bar = "#" * count
        print(f"  {cat:<12}: {count} {bar}")
    
    # Compute counts
    web_count = cats.get("web", 0)
    crypto_count = cats.get("crypto", 0)
    binary_count = cats.get("pwn", 0) + cats.get("reverse", 0)
    misc_count = cats.get("misc", 0)
    blockchain_count = cats.get("blockchain", 0)
    
    print(f"\n--- Solvability Assessment ---")
    print(f"  Web ({web_count}): Need container URLs -> WebSmartSolver ready")
    print(f"  Crypto ({crypto_count}): Need ciphertext -> CryptoSmartSolver ready")
    print(f"  PWN/Reverse ({binary_count}): Need binary files -> BinaryAnalyzer ready")
    print(f"  Misc ({misc_count}): Need files -> MiscAnalyzer ready")
    print(f"  Blockchain ({blockchain_count}): Need source/bytecode -> BlockchainAnalyzer ready")
    print(f"\n  NOTE: All 20 problems need CTF+ authentication to access containers/attachments")


if __name__ == "__main__":
    problems = load_problems()
    print_header()
    print(f"\nLoaded {len(problems)} problems from CTF+ favorites")
    analyze_problems(problems)
    
    # Check for dry-run flag
    if "--dry-run" in sys.argv or len(sys.argv) == 1:
        print(f"\nAnalysis complete. To actually solve:")
        print(f"   1. Start Docker containers on CTF+ for Web/PWN problems")
        print(f"   2. Download attachments for static problems")
        print(f"   3. Create ctfplus_containers.json: {{\"problem_id\": \"http://url:port\"}}")
        print(f"   4. Run: python ctfplus_batch_solver.py --solve")
        sys.exit(0)
    
    if "--solve" in sys.argv:
        containers_file = 'ctfplus_containers.json'
        attachments_file = 'ctfplus_attachments_map.json'
        
        containers = {}
        attachments = {}
        
        if os.path.exists(containers_file):
            with open(containers_file, 'r') as f:
                containers = json.load(f)
        
        if os.path.exists(attachments_file):
            with open(attachments_file, 'r') as f:
                attachments = json.load(f)
        
        print(f"\nStarting batch solve...")
        print(f"   Containers: {len(containers)} | Attachments: {len(attachments)}")
        
        solver = SmartSolver()
        results = solver.batch_solve(problems, containers, attachments)
        solver.print_summary(results)
        
        # Save results
        with open('ctfplus_solve_results.json', 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"\nResults saved to ctfplus_solve_results.json")
