# -*- coding: utf-8 -*-
"""
Main Orchestrator
Reads SAST report, filters CRITICAL/HIGH/MEDIUM,
validates each finding using AI + MobSF DAST
"""

import json
import os
import sys
import time

# Fix Windows encoding
sys.stdout.reconfigure(encoding='utf-8') if hasattr(sys.stdout, 'reconfigure') else None

from mobsf_tools import MobSFTools
from claude_agent import ClaudeAgent


# -----------------------------------------
# CONFIG
# -----------------------------------------

MOBSF_SERVER   = os.getenv('MOBSF_SERVER',   'http://localhost:8000')
MOBSF_API_KEY  = os.getenv('MOBSF_API_KEY',  '')
CLAUDE_API_KEY = os.getenv('CLAUDE_API_KEY', '')
PACKAGE_NAME   = os.getenv('PACKAGE_NAME',   'infosecadventures.allsafe')
OUTPUT_DIR     = os.getenv('OUTPUT_DIR',     'validation_output')

SAST_REPORT    = sys.argv[1] if len(sys.argv) > 1 else 'sast_report.json'
DAST_REPORT    = sys.argv[2] if len(sys.argv) > 2 else 'dast_report.json'
FILE_HASH      = sys.argv[3] if len(sys.argv) > 3 else ''

os.makedirs(OUTPUT_DIR, exist_ok=True)


# -----------------------------------------
# LOAD REPORTS
# -----------------------------------------

def load_reports():
    print('\n[*] Loading reports...')

    with open(SAST_REPORT, encoding='utf-8') as f:
        sast = json.load(f)
    print('  [OK] SAST report loaded')

    dast = {}
    try:
        with open(DAST_REPORT, encoding='utf-8') as f:
            dast = json.load(f)
        print('  [OK] DAST report loaded')
    except Exception:
        print('  [WARN] DAST report not found, continuing...')

    return sast, dast


# -----------------------------------------
# FILTER CRITICAL + HIGH + MEDIUM FINDINGS
# -----------------------------------------

def get_findings(sast_data):
    print('\n[*] Filtering CRITICAL/HIGH/MEDIUM findings...')
    findings = []

    SEVERITY_FILTER = ['CRITICAL', 'HIGH', 'MEDIUM']
    SEVERITY_ORDER  = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}

    # From code analysis
    code_analysis = sast_data.get('code_analysis', {}).get('findings', {})
    for rule_id, finding in code_analysis.items():
        severity = finding.get('metadata', {}).get('severity', '').upper()
        if severity in SEVERITY_FILTER:
            findings.append({
                'id':          rule_id,
                'title':       finding.get('metadata', {}).get(
                               'description', rule_id),
                'severity':    severity,
                'cvss':        finding.get('metadata', {}).get('cvss', 0),
                'cwe':         finding.get('metadata', {}).get('cwe', 'N/A'),
                'owasp':       finding.get('metadata', {}).get(
                               'owasp-mobile', 'N/A'),
                'description': finding.get('metadata', {}).get(
                               'description', ''),
                'files':       finding.get('files', {}),
                'source':      'code_analysis'
            })

    # From binary analysis
    binary = sast_data.get('binary_analysis', {})
    for rule_id, finding in binary.items():
        if isinstance(finding, dict):
            severity = finding.get('severity', '').upper()
            if severity in SEVERITY_FILTER:
                findings.append({
                    'id':          f'binary_{rule_id}',
                    'title':       finding.get('description', rule_id),
                    'severity':    severity,
                    'cvss':        finding.get('cvss', 0),
                    'cwe':         finding.get('cwe', 'N/A'),
                    'owasp':       finding.get('owasp', 'N/A'),
                    'description': finding.get('description', ''),
                    'files':       {},
                    'source':      'binary_analysis'
                })

    # Sort: CRITICAL -> HIGH -> MEDIUM
    findings.sort(key=lambda x: SEVERITY_ORDER.get(x['severity'], 3))

    # Print counts
    critical = sum(1 for f in findings if f['severity'] == 'CRITICAL')
    high     = sum(1 for f in findings if f['severity'] == 'HIGH')
    medium   = sum(1 for f in findings if f['severity'] == 'MEDIUM')

    print(f'  Found {len(findings)} findings')
    print(f'  CRITICAL: {critical} | HIGH: {high} | MEDIUM: {medium}')

    return findings


# -----------------------------------------
# GET SOURCE CODE SNIPPET
# -----------------------------------------

def get_source_snippet(finding, workspace='.'):
    snippets = []
    files    = finding.get('files', {})

    for filepath, file_data in list(files.items())[:2]:
        try:
            full_path = os.path.join(workspace, filepath)
            if os.path.exists(full_path):
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()

                line_nums = []
                if isinstance(file_data, dict):
                    line_nums = list(file_data.keys())[:3]

                if line_nums:
                    for line_str in line_nums:
                        try:
                            line_num = int(line_str)
                            start    = max(0, line_num - 5)
                            end      = min(len(lines), line_num + 5)
                            snippet  = ''.join(lines[start:end])
                            snippets.append(
                                f'File: {filepath} (line {line_num}):\n'
                                f'```\n{snippet}\n```'
                            )
                        except Exception:
                            pass
        except Exception:
            pass

    return '\n\n'.join(snippets) if snippets else None


# -----------------------------------------
# SAVE RESULTS
# -----------------------------------------

def save_results(all_results):
    output = []
    for r in all_results:
        output.append({
            'finding_id':  r['finding']['id'],
            'title':       r['finding']['title'],
            'severity':    r['finding']['severity'],
            'cwe':         r['finding'].get('cwe', 'N/A'),
            'owasp':       r['finding'].get('owasp', 'N/A'),
            'cvss':        r['finding'].get('cvss', 0),
            'verdict':     r['verdict']['verdict'],
            'confidence':  r['verdict']['confidence'],
            'explanation': r['verdict']['explanation'],
            'evidence_summary': r['verdict'].get('evidence_summary', ''),
            'fix':         r['verdict']['fix_recommendation'],
            'risk_score':  r['verdict']['risk_score'],
            'screenshots': r['verdict'].get('screenshots', [])
        })

    results_path = os.path.join(OUTPUT_DIR, 'validation_results.json')
    with open(results_path, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2)

    print(f'\n  [OK] Results saved: {results_path}')
    return results_path


# -----------------------------------------
# PRINT SUMMARY
# -----------------------------------------

def print_summary(all_results):
    print('\n' + '='*55)
    print('  VALIDATION SUMMARY')
    print('='*55)

    confirmed = [r for r in all_results
                 if r['verdict']['verdict'] == 'CONFIRMED']
    false_pos = [r for r in all_results
                 if r['verdict']['verdict'] == 'FALSE_POSITIVE']
    needs_rev = [r for r in all_results
                 if r['verdict']['verdict'] == 'NEEDS_REVIEW']

    print(f'  Total Findings : {len(all_results)}')
    print(f'  Confirmed      : {len(confirmed)}')
    print(f'  False Positive : {len(false_pos)}')
    print(f'  Needs Review   : {len(needs_rev)}')
    print('='*55)

    if confirmed:
        print('\n  CONFIRMED FINDINGS:')
        for r in confirmed:
            print(f'    [{r["finding"]["severity"]}] '
                  f'{r["finding"]["title"][:50]} '
                  f'(Risk: {r["verdict"]["risk_score"]}/10)')

    if false_pos:
        print('\n  FALSE POSITIVES:')
        for r in false_pos:
            print(f'    [{r["finding"]["severity"]}] '
                  f'{r["finding"]["title"][:50]}')

    if needs_rev:
        print('\n  NEEDS MANUAL REVIEW:')
        for r in needs_rev:
            print(f'    [{r["finding"]["severity"]}] '
                  f'{r["finding"]["title"][:50]}')

    print(f'\n  Reports saved in: {OUTPUT_DIR}')
    print('='*55)


# -----------------------------------------
# MAIN
# -----------------------------------------

if __name__ == '__main__':

    print('\n' + '='*55)
    print('  MobSF SAST Validation with AI')
    print('='*55)

    # Validate config
    if not MOBSF_API_KEY:
        print('[ERROR] MOBSF_API_KEY not set!')
        sys.exit(1)

    if not CLAUDE_API_KEY:
        print('[ERROR] CLAUDE_API_KEY (Groq key) not set!')
        sys.exit(1)

    if not FILE_HASH:
        print('[ERROR] FILE_HASH not provided!')
        sys.exit(1)

    print(f'  MOBSF_SERVER : {MOBSF_SERVER}')
    print(f'  PACKAGE      : {PACKAGE_NAME}')
    print(f'  FILE_HASH    : {FILE_HASH}')
    print(f'  OUTPUT_DIR   : {OUTPUT_DIR}')

    # Load reports
    sast, dast = load_reports()

    # Get findings
    findings = get_findings(sast)

    if not findings:
        print('\n[OK] No CRITICAL/HIGH/MEDIUM findings - pipeline passes!')
        sys.exit(0)

    # Init MobSF tools
    print('\n[*] Initializing MobSF tools...')
    mobsf = MobSFTools(
        server     = MOBSF_SERVER,
        api_key    = MOBSF_API_KEY,
        hash_val   = FILE_HASH,
        output_dir = OUTPUT_DIR
    )

    # Init AI agent
    print('[*] Initializing AI agent (Groq)...')
    agent = ClaudeAgent(
        api_key      = CLAUDE_API_KEY,
        mobsf_tools  = mobsf,
        package_name = PACKAGE_NAME
    )

    # Validate each finding
    all_results = []
    total       = len(findings)

    for i, finding in enumerate(findings):
        print(f'\n[{i+1}/{total}] Processing: '
              f'[{finding["severity"]}] {finding["title"][:50]}')

        # Get source code context
        snippet = get_source_snippet(finding)

        # Run full validation
        result = agent.validate_finding(finding, snippet)
        all_results.append(result)

        # Delay between findings
        if i < total - 1:
            print('  [*] Waiting before next finding...')
            time.sleep(2)

    # Save results
    save_results(all_results)

    # Print summary
    print_summary(all_results)

    print('\n[OK] Validation complete! Proceeding to report generation...')
    sys.exit(0)
