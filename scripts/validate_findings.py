# -*- coding: utf-8 -*-
"""
Main Orchestrator - IMPROVED VERSION
Expanded finding coverage: code_analysis, binary_analysis,
manifest_analysis, network_security, permissions, urls,
firebase, exported components, hardcoded secrets
"""

import json
import os
import sys
import time

# Fix Windows encoding
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

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

SEVERITY_FILTER = ['CRITICAL', 'HIGH', 'MEDIUM']
SEVERITY_ORDER  = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}


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
# FINDING EXTRACTORS (one per source)
# -----------------------------------------

def extract_code_analysis(sast_data):
    findings = []
    code = sast_data.get('code_analysis', {}).get('findings', {})
    for rule_id, item in code.items():
        sev = item.get('metadata', {}).get('severity', '').upper()
        if sev in SEVERITY_FILTER:
            findings.append({
                'id':          rule_id,
                'title':       item.get('metadata', {}).get('description', rule_id),
                'severity':    sev,
                'cvss':        item.get('metadata', {}).get('cvss', 0),
                'cwe':         item.get('metadata', {}).get('cwe', 'N/A'),
                'owasp':       item.get('metadata', {}).get('owasp-mobile', 'N/A'),
                'description': item.get('metadata', {}).get('description', ''),
                'files':       item.get('files', {}),
                'source':      'code_analysis'
            })
    return findings


def extract_binary_analysis(sast_data):
    findings = []
    raw = sast_data.get('binary_analysis', [])
    if isinstance(raw, dict):
        items = list(raw.values())
    elif isinstance(raw, list):
        items = raw
    else:
        items = []

    for i, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        sev = item.get('severity', '').upper()
        if sev in SEVERITY_FILTER:
            findings.append({
                'id':          f'binary_{i}',
                'title':       item.get('description', item.get('name', f'Binary Issue {i}')),
                'severity':    sev,
                'cvss':        item.get('cvss', 0),
                'cwe':         item.get('cwe', 'N/A'),
                'owasp':       item.get('owasp', 'N/A'),
                'description': item.get('description', ''),
                'files':       {},
                'source':      'binary_analysis'
            })
    return findings


def extract_manifest_analysis(sast_data):
    """Extract dangerous manifest issues: exported components, debug flags, backup enabled, etc."""
    findings = []
    manifest = sast_data.get('manifest_analysis', {})

    # MobSF manifest findings dict
    manifest_findings = manifest.get('manifest_findings', [])
    if isinstance(manifest_findings, list):
        for item in manifest_findings:
            sev = item.get('severity', '').upper()
            if sev not in SEVERITY_FILTER:
                continue
            findings.append({
                'id':          f'manifest_{item.get("rule", len(findings))}',
                'title':       item.get('title', 'Manifest Issue'),
                'severity':    sev,
                'cvss':        0,
                'cwe':         item.get('cwe', 'N/A'),
                'owasp':       item.get('owasp', 'N/A'),
                'description': item.get('description', item.get('title', '')),
                'files':       {},
                'source':      'manifest_analysis',
                'detail':      item.get('component', '')
            })

    # Explicit flags — only add if NOT already covered by manifest_findings above.
    # Use keyword matching (not exact title) to catch MobSF's own wording variants,
    # e.g. "Debug Enabled For App [android:debuggable=true]" covers our "DEBUG FLAG ENABLED".
    FLAG_KEYWORDS = {
        'android:debuggable':            ['debuggable', 'debug enabled', 'debug flag'],
        'android:allowBackup':           ['backup', 'allowbackup', 'allow backup'],
        'android:usesCleartextTraffic':  ['cleartext', 'clear text', 'cleartraffic'],
        'android:exported=true':         ['exported component', 'exported activity',
                                          'exported service', 'exported receiver'],
        'android:networkSecurityConfig': ['network security config', 'networksecurityconfig',
                                          'networksecurity'],
    }

    flags = {
        'android:debuggable':            ('DEBUG FLAG ENABLED',            'CRITICAL', 'CWE-489'),
        'android:allowBackup':           ('BACKUP ENABLED',                'HIGH',     'CWE-312'),
        'android:usesCleartextTraffic':  ('CLEARTEXT TRAFFIC ALLOWED',     'HIGH',     'CWE-319'),
        'android:exported=true':         ('EXPORTED COMPONENT',            'HIGH',     'CWE-926'),
        'android:networkSecurityConfig': ('CUSTOM NETWORK SECURITY CONFIG','MEDIUM',   'CWE-319'),
    }

    manifest_str = json.dumps(manifest).lower()
    for flag, (title, sev, cwe) in flags.items():
        if flag.lower() not in manifest_str:
            continue
        if sev not in SEVERITY_FILTER:
            continue

        # Check if ANY existing finding already covers this flag via keywords
        keywords = FLAG_KEYWORDS.get(flag, [title.lower()])
        already  = any(
            any(kw in f['title'].lower() or kw in f['description'].lower()
                for kw in keywords)
            for f in findings
        )
        if not already:
            findings.append({
                'id':          f'manifest_flag_{flag.replace(":", "_").replace("=", "_")}',
                'title':       title,
                'severity':    sev,
                'cvss':        0,
                'cwe':         cwe,
                'owasp':       'M1: Improper Platform Usage',
                'description': f'AndroidManifest.xml contains {flag}',
                'files':       {},
                'source':      'manifest_analysis'
            })

    return findings


def extract_network_security(sast_data):
    """Custom network security config issues, certificate pinning bypass, etc."""
    findings = []
    network = sast_data.get('network_security', {})

    # network_findings list
    for item in network.get('network_findings', []):
        sev = item.get('severity', '').upper()
        if sev in SEVERITY_FILTER:
            findings.append({
                'id':          f'network_{len(findings)}',
                'title':       item.get('issue', item.get('name', 'Network Security Issue')),
                'severity':    sev,
                'cvss':        0,
                'cwe':         item.get('cwe', 'CWE-295'),
                'owasp':       'M3: Insecure Communication',
                'description': item.get('description', ''),
                'files':       {},
                'source':      'network_security'
            })

    # High-value flags
    net_str = json.dumps(network).lower()
    if '"cleartexttrafficpermitted": true' in net_str or 'cleartexttrafficpermitted' in net_str:
        findings.append({
            'id':          'network_cleartext',
            'title':       'CLEARTEXT TRAFFIC PERMITTED IN NETWORK CONFIG',
            'severity':    'HIGH',
            'cvss':        6.5,
            'cwe':         'CWE-319',
            'owasp':       'M3: Insecure Communication',
            'description': 'Network security config permits cleartext (HTTP) traffic',
            'files':       {},
            'source':      'network_security'
        })

    if '"acceptsuserscertificates": true' in net_str or 'acceptsuserscertificates' in net_str:
        findings.append({
            'id':          'network_user_certs',
            'title':       'USER-INSTALLED CERTIFICATES TRUSTED',
            'severity':    'HIGH',
            'cvss':        7.0,
            'cwe':         'CWE-295',
            'owasp':       'M3: Insecure Communication',
            'description': 'App trusts user-installed CA certificates, enabling MITM attacks',
            'files':       {},
            'source':      'network_security'
        })

    return findings


def extract_permissions(sast_data):
    """Dangerous Android permissions."""
    findings = []
    DANGEROUS = {
        'READ_CONTACTS':         ('HIGH',   'CWE-359', 'M1'),
        'WRITE_CONTACTS':        ('HIGH',   'CWE-359', 'M1'),
        'ACCESS_FINE_LOCATION':  ('HIGH',   'CWE-359', 'M1'),
        'ACCESS_COARSE_LOCATION':('MEDIUM', 'CWE-359', 'M1'),
        'READ_CALL_LOG':         ('HIGH',   'CWE-359', 'M1'),
        'READ_SMS':              ('HIGH',   'CWE-359', 'M1'),
        'RECEIVE_SMS':           ('HIGH',   'CWE-359', 'M1'),
        'CAMERA':                ('MEDIUM', 'CWE-359', 'M1'),
        'RECORD_AUDIO':          ('HIGH',   'CWE-359', 'M1'),
        'READ_EXTERNAL_STORAGE': ('MEDIUM', 'CWE-312', 'M2'),
        'WRITE_EXTERNAL_STORAGE':('MEDIUM', 'CWE-312', 'M2'),
        'GET_ACCOUNTS':          ('MEDIUM', 'CWE-359', 'M1'),
        'USE_BIOMETRIC':         ('MEDIUM', 'CWE-287', 'M4'),
        'USE_FINGERPRINT':       ('MEDIUM', 'CWE-287', 'M4'),
    }

    perms = sast_data.get('permissions', {})
    if isinstance(perms, dict):
        perm_list = list(perms.keys())
    elif isinstance(perms, list):
        perm_list = perms
    else:
        perm_list = []

    for perm in perm_list:
        perm_name = perm.replace('android.permission.', '').upper()
        if perm_name in DANGEROUS:
            sev, cwe, owasp = DANGEROUS[perm_name]
            findings.append({
                'id':          f'perm_{perm_name}',
                'title':       f'DANGEROUS PERMISSION: {perm_name}',
                'severity':    sev,
                'cvss':        0,
                'cwe':         cwe,
                'owasp':       f'{owasp}: Improper Platform Usage',
                'description': f'App requests dangerous permission: {perm}',
                'files':       {},
                'source':      'permissions'
            })

    return findings


def extract_secrets(sast_data):
    """Hardcoded API keys, passwords, tokens."""
    findings = []
    secrets = sast_data.get('secrets', [])
    if isinstance(secrets, list):
        for i, item in enumerate(secrets):
            if isinstance(item, dict):
                findings.append({
                    'id':          f'secret_{i}',
                    'title':       f'HARDCODED SECRET: {item.get("type", "Unknown")}',
                    'severity':    'HIGH',
                    'cvss':        7.5,
                    'cwe':         'CWE-798',
                    'owasp':       'M9: Reverse Engineering',
                    'description': f'Hardcoded secret found: {item.get("match", "")} in {item.get("file", "")}',
                    'files':       {item.get('file', ''): {}},
                    'source':      'secrets'
                })
    return findings


def extract_firebase(sast_data):
    """Firebase misconfiguration."""
    findings = []
    firebase = sast_data.get('firebase_urls', [])
    if isinstance(firebase, list) and firebase:
        findings.append({
            'id':          'firebase_exposed',
            'title':       'FIREBASE DATABASE URLs EXPOSED',
            'severity':    'HIGH',
            'cvss':        7.5,
            'cwe':         'CWE-200',
            'owasp':       'M2: Insecure Data Storage',
            'description': f'Firebase URLs found in app: {", ".join(str(u) for u in firebase[:3])}',
            'files':       {},
            'source':      'firebase'
        })
    return findings


def extract_urls(sast_data):
    """Interesting hardcoded URLs (HTTP, private IPs, etc.)."""
    findings = []
    urls = sast_data.get('urls', [])
    http_urls = []

    for item in urls:
        if isinstance(item, dict):
            url = item.get('url', '')
        else:
            url = str(item)

        if url.startswith('http://') and not url.startswith('http://localhost'):
            http_urls.append(url)

    if http_urls:
        findings.append({
            'id':          'hardcoded_http_urls',
            'title':       f'HARDCODED HTTP URLs ({len(http_urls)} found)',
            'severity':    'MEDIUM',
            'cvss':        4.3,
            'cwe':         'CWE-319',
            'owasp':       'M3: Insecure Communication',
            'description': f'Hardcoded insecure HTTP URLs: {", ".join(http_urls[:5])}',
            'files':       {},
            'source':      'urls'
        })

    return findings


# -----------------------------------------
# MASTER: GET ALL FINDINGS
# -----------------------------------------

def get_findings(sast_data):
    print('\n[*] Scanning all MobSF finding sources...')
    all_findings = []
    seen_ids = set()

    sources = [
        ('Code Analysis',       extract_code_analysis),
        ('Binary Analysis',     extract_binary_analysis),
        ('Manifest Analysis',   extract_manifest_analysis),
        ('Network Security',    extract_network_security),
        ('Permissions',         extract_permissions),
        ('Hardcoded Secrets',   extract_secrets),
        ('Firebase',            extract_firebase),
        ('Hardcoded URLs',      extract_urls),
    ]

    for label, extractor in sources:
        try:
            results = extractor(sast_data)
            # Deduplicate by id
            unique = []
            for f in results:
                if f['id'] not in seen_ids:
                    seen_ids.add(f['id'])
                    unique.append(f)
            print(f'  [{label}] {len(unique)} findings')
            all_findings.extend(unique)
        except Exception as e:
            print(f'  [WARN] {label} extractor failed: {e}')

    # Sort: CRITICAL -> HIGH -> MEDIUM
    all_findings.sort(key=lambda x: SEVERITY_ORDER.get(x['severity'], 3))

    critical = sum(1 for f in all_findings if f['severity'] == 'CRITICAL')
    high     = sum(1 for f in all_findings if f['severity'] == 'HIGH')
    medium   = sum(1 for f in all_findings if f['severity'] == 'MEDIUM')

    print(f'\n  TOTAL: {len(all_findings)} findings')
    print(f'  CRITICAL: {critical} | HIGH: {high} | MEDIUM: {medium}')

    return all_findings


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
# SAVE RESULTS (always saves even if empty)
# -----------------------------------------

def save_results(all_results):
    output = []
    for r in all_results:
        output.append({
            'finding_id':       r['finding']['id'],
            'title':            r['finding']['title'],
            'severity':         r['finding']['severity'],
            'cwe':              r['finding'].get('cwe', 'N/A'),
            'owasp':            r['finding'].get('owasp', 'N/A'),
            'cvss':             r['finding'].get('cvss', 0),
            'source':           r['finding'].get('source', 'unknown'),
            'verdict':          r['verdict']['verdict'],
            'confidence':       r['verdict']['confidence'],
            'explanation':      r['verdict']['explanation'],
            'evidence_summary': r['verdict'].get('evidence_summary', ''),
            'fix':              r['verdict'].get('fix_recommendation', ''),
            'risk_score':       r['verdict'].get('risk_score', 5),
            'screenshots':      r['verdict'].get('screenshots', [])
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

    confirmed = [r for r in all_results if r['verdict']['verdict'] == 'CONFIRMED']
    false_pos = [r for r in all_results if r['verdict']['verdict'] == 'FALSE_POSITIVE']
    needs_rev = [r for r in all_results if r['verdict']['verdict'] == 'NEEDS_REVIEW']

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
            print(f'    [{r["finding"]["severity"]}] {r["finding"]["title"][:50]}')

    if needs_rev:
        print('\n  NEEDS MANUAL REVIEW:')
        for r in needs_rev:
            print(f'    [{r["finding"]["severity"]}] {r["finding"]["title"][:50]}')

    print(f'\n  Reports saved in: {OUTPUT_DIR}')
    print('='*55)


# -----------------------------------------
# MAIN
# -----------------------------------------

if __name__ == '__main__':

    print('\n' + '='*55)
    print('  MobSF SAST Validation with Groq AI  v2.0')
    print('='*55)

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

    sast, dast = load_reports()
    findings   = get_findings(sast)

    # Always save results file even if 0 findings
    results_path = os.path.join(OUTPUT_DIR, 'validation_results.json')
    if not findings:
        print('\n[OK] No CRITICAL/HIGH/MEDIUM findings - pipeline passes!')
        with open(results_path, 'w', encoding='utf-8') as f:
            json.dump([], f, indent=2)
        print(f'  [OK] Empty results saved: {results_path}')
        sys.exit(0)

    # Init MobSF tools
    print('\n[*] Initializing MobSF tools...')
    mobsf = MobSFTools(
        server       = MOBSF_SERVER,
        api_key      = MOBSF_API_KEY,
        hash_val     = FILE_HASH,
        output_dir   = OUTPUT_DIR,
        package_name = PACKAGE_NAME
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
        print(f'\n[{i+1}/{total}] [{finding["severity"]}] {finding["title"][:55]}')
        snippet = get_source_snippet(finding)
        result  = agent.validate_finding(finding, snippet)
        all_results.append(result)

        if i < total - 1:
            print('  [*] Cooling down before next finding...')
            time.sleep(3)

    save_results(all_results)
    print_summary(all_results)

    print('\n[OK] Validation complete! Proceeding to report generation...')
    sys.exit(0)