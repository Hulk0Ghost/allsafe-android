# -*- coding: utf-8 -*-
"""
Claude Agent - Groq AI Integration  v2.0
Improved prompts with Android-specific security context
Model: llama-3.3-70b-versatile
"""

import json
import requests
import os

# Fix Windows encoding
import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')


# -----------------------------------------
# ANDROID SECURITY CONTEXT
# Used to give Groq deep Android knowledge
# -----------------------------------------

ANDROID_SECURITY_CONTEXT = """
You are a senior Android penetration tester and mobile security expert with 10+ years of experience.
You have deep knowledge of:

OWASP Mobile Top 10:
- M1: Improper Platform Usage (exported components, permissions misuse)
- M2: Insecure Data Storage (SharedPrefs, SQLite, external storage, logs)
- M3: Insecure Communication (HTTP, certificate pinning, custom trust managers)
- M4: Insecure Authentication (biometric bypass, weak session tokens)
- M5: Insufficient Cryptography (ECB mode, hardcoded keys, MD5/SHA1)
- M6: Insecure Authorization (broken access control, intent hijacking)
- M7: Client Code Quality (buffer overflows, format strings, XSS in WebView)
- M8: Code Tampering (debug flags, root detection bypass)
- M9: Reverse Engineering (hardcoded secrets, obfuscation bypass)
- M10: Extraneous Functionality (hidden backdoors, test code in prod)

Android-Specific Attack Vectors:
- Intent injection / exported activity hijacking
- Content provider SQL injection
- WebView JavaScript interface attacks
- Tapjacking / overlay attacks
- Broadcast receiver abuse
- Deep link exploitation
- Certificate pinning bypass via Frida/Objection
- Root detection bypass
- Backup extraction (adb backup)
- Logcat data leakage
- Clipboard hijacking

Common False Positive Patterns:
- Reflection usage in popular libraries (Gson, Retrofit, Glide)
- Cryptography in test/debug code only
- Exported components that require caller permissions
- HTTP allowed only for localhost/loopback
- Deprecated APIs used by third-party SDKs (not app code)
- Generic boilerplate code from IDE templates
"""

# Maps finding source to attack context
SOURCE_CONTEXT = {
    'manifest_analysis': 'Focus on: exported components without permissions, debug=true, backup=true, cleartext traffic, task hijacking via launchMode.',
    'code_analysis':     'Focus on: actual code reachability, whether the vulnerable code path is triggered, hardcoded credentials, insecure crypto usage.',
    'binary_analysis':   'Focus on: stack protection, PIE, RELRO, anti-debugging - consider if these are exploitable in practice.',
    'network_security':  'Focus on: MITM feasibility, whether the app uses certificate pinning, TLS version, and real network traffic patterns.',
    'permissions':       'Focus on: whether the permission is actually used in code, if it can be abused by other apps, and permission escalation risks.',
    'secrets':           'Focus on: whether the secret grants real access (not expired/revoked/test key), scope of access it provides.',
    'firebase':          'Focus on: whether the Firebase DB has public read/write rules, test with unauthenticated access.',
    'urls':              'Focus on: whether HTTP endpoints transmit sensitive data, authentication tokens, or PII.',
}


class ClaudeAgent:

    def __init__(self, api_key, mobsf_tools, package_name):
        self.api_key  = api_key
        self.tools    = mobsf_tools
        self.package  = package_name
        self.model    = 'llama-3.3-70b-versatile'
        self.api_url  = 'https://api.groq.com/openai/v1/chat/completions'
        self.headers  = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type':  'application/json'
        }

    # -----------------------------------------
    # CALL GROQ API
    # -----------------------------------------

    def ask_groq(self, system_prompt, user_message, max_tokens=2000):
        try:
            payload = {
                'model':       self.model,
                'max_tokens':  max_tokens,
                'temperature': 0.1,   # Low temp = more consistent verdicts
                'messages': [
                    {'role': 'system', 'content': system_prompt},
                    {'role': 'user',   'content': user_message}
                ]
            }
            r = requests.post(
                self.api_url,
                headers=self.headers,
                json=payload,
                timeout=60
            )
            response = r.json()

            if 'choices' in response:
                return response['choices'][0]['message']['content']
            else:
                print(f'  [WARN] Groq error: {response.get("error", response)}')
                return None

        except Exception as e:
            print(f'  [WARN] Groq API failed: {e}')
            return None

    # -----------------------------------------
    # STEP 1: GET TEST PLAN
    # -----------------------------------------

    def get_test_plan(self, finding, source_code_snippet=None):
        print(f'  [AI] Analyzing: {finding["title"][:55]}')

        source      = finding.get('source', 'code_analysis')
        tool_list   = json.dumps(self.tools.get_tool_list(), indent=2)
        src_context = SOURCE_CONTEXT.get(source, '')

        source_section = ''
        if source_code_snippet:
            source_section = f"""
RELEVANT SOURCE CODE (use this to assess real reachability):
{source_code_snippet}
"""

        system_prompt = ANDROID_SECURITY_CONTEXT + """

Your task: given a SAST finding, design a minimal but targeted DAST test plan to CONFIRM or DENY it.
Be precise. Use the minimum steps needed - don't waste API calls on irrelevant tools.
You MUST respond with ONLY valid JSON - no markdown, no explanation, no code blocks.
"""

        user_message = f"""
FINDING TO VALIDATE:
  ID:          {finding['id']}
  Title:       {finding['title']}
  Severity:    {finding['severity']}
  CWE:         {finding['cwe']}
  OWASP:       {finding['owasp']}
  Source:      {source}
  Description: {finding['description']}
  Files:       {json.dumps(list(finding.get('files', {}).keys())[:3])}

SPECIFIC FOCUS FOR THIS SOURCE TYPE:
{src_context}
{source_section}

AVAILABLE MOBSF DAST TOOLS:
{tool_list}

APP PACKAGE: {self.package}

Design a targeted test plan. Be specific about WHAT evidence would confirm or deny this finding.
Respond with ONLY this JSON (raw, no markdown):

{{
  "test_plan": [
    {{
      "step": 1,
      "tool": "tool_name",
      "params": {{"key": "value"}},
      "reason": "exactly what this step will reveal about the finding"
    }}
  ],
  "what_to_look_for": "specific evidence that CONFIRMS the finding (be precise, e.g. exact log strings, HTTP endpoints, file paths)",
  "false_positive_indicators": "specific evidence that suggests this is a FALSE POSITIVE (e.g. code only in test class, library code, never executed path)",
  "severity_justification": "why this severity level is or isn't appropriate for this specific app context"
}}
"""

        response = self.ask_groq(system_prompt, user_message)

        if not response:
            return self._default_test_plan(finding)

        try:
            clean = response.strip()
            if '```' in clean:
                parts = clean.split('```')
                for part in parts:
                    if part.strip().startswith('{'):
                        clean = part.strip()
                        break
                else:
                    clean = parts[1]
                    if clean.startswith('json'):
                        clean = clean[4:]

            start = clean.find('{')
            end   = clean.rfind('}') + 1
            if start != -1 and end > start:
                clean = clean[start:end]
            return json.loads(clean)
        except Exception as e:
            print(f'  [WARN] Could not parse test plan JSON: {e}')
            return self._default_test_plan(finding)

    # -----------------------------------------
    # STEP 2: EXECUTE TEST PLAN
    # -----------------------------------------

    def execute_test_plan(self, test_plan, finding_id):
        steps   = test_plan.get('test_plan', [])
        results = []
        print(f'  [*] Executing {len(steps)} DAST steps...')

        for step in steps:
            tool_name = step['tool']
            params    = step.get('params', {})
            reason    = step.get('reason', '')

            print(f'    Step {step["step"]}: {tool_name} - {reason[:60]}')
            result = self._call_tool(tool_name, params, finding_id)
            results.append({
                'step':   step['step'],
                'tool':   tool_name,
                'params': params,
                'reason': reason,
                'result': result
            })

        return results

    # -----------------------------------------
    # TOOL DISPATCHER
    # -----------------------------------------

    def _call_tool(self, tool_name, params, finding_id):
        safe_id  = finding_id.replace('/', '_').replace(' ', '_')
        dispatch = {
            'start_activity':           lambda: self.tools.start_activity(params.get('activity', '')),
            'launch_app':               lambda: self.tools.launch_app(params.get('package', self.package)),
            'stop_app':                 lambda: self.tools.stop_app(params.get('package', self.package)),
            'adb_input_text':           lambda: self.tools.adb_input_text(params.get('text', '')),
            'adb_tap':                  lambda: self.tools.adb_tap(params.get('x', 500), params.get('y', 500)),
            'adb_press_key':            lambda: self.tools.adb_press_key(params.get('keycode', 66)),
            'take_screenshot':          lambda: self.tools.take_screenshot(f'{safe_id}_step{params.get("step", 1)}'),
            'start_pcap':               lambda: self.tools.start_pcap(),
            'stop_pcap':                lambda: self.tools.stop_pcap(),
            'get_http_logs':            lambda: self.tools.get_http_logs(),
            'get_frida_logs':           lambda: self.tools.get_frida_logs(),
            'run_frida_script':         lambda: self.tools.run_frida_script(),
            'run_named_frida_script':   lambda: self.tools.run_named_frida_script(params.get('script_name', 'api_monitor')),
            'get_logcat':               lambda: self.tools.get_logcat(),
            'test_exported_activities': lambda: self.tools.test_exported_activities(),
        }

        if tool_name in dispatch:
            try:
                return dispatch[tool_name]()
            except Exception as e:
                return {'success': False, 'error': str(e)}
        else:
            print(f'  [WARN] Unknown tool: {tool_name}')
            return {'success': False, 'error': f'Unknown tool: {tool_name}'}

    # -----------------------------------------
    # STEP 3: GET VERDICT (improved prompts)
    # -----------------------------------------

    def get_verdict(self, finding, test_plan, execution_results):
        print(f'  [AI] Analyzing evidence for verdict...')

        source      = finding.get('source', 'code_analysis')
        src_context = SOURCE_CONTEXT.get(source, '')

        # Build structured evidence summary
        evidence_items   = []
        screenshots      = []
        http_data        = None
        logcat_data      = None
        frida_data       = None

        for r in execution_results:
            tool   = r['tool']
            result = r['result']
            step   = r['step']

            if tool == 'take_screenshot' and result.get('success'):
                screenshots.append(result.get('path', ''))
                evidence_items.append(f'Step {step}: Screenshot captured at {result.get("path", "")}')

            elif tool == 'get_http_logs' and result.get('success'):
                data = result.get('data', {})
                http_data = json.dumps(data)[:800]
                evidence_items.append(f'Step {step}: HTTP traffic captured: {http_data}')

            elif tool == 'get_frida_logs' and result.get('success'):
                data = result.get('data', {})
                frida_data = json.dumps(data)[:600]
                evidence_items.append(f'Step {step}: Frida logs: {frida_data}')

            elif tool == 'get_logcat' and result.get('success'):
                data = result.get('data', {})
                logcat_data = json.dumps(data)[:600]
                evidence_items.append(f'Step {step}: Logcat: {logcat_data}')

            elif result.get('success'):
                evidence_items.append(f'Step {step}: {tool} succeeded - {json.dumps(result.get("data", {}))[:200]}')

            else:
                evidence_items.append(f'Step {step}: {tool} failed - {result.get("error", "unknown error")}')

        evidence_str = '\n'.join(evidence_items) if evidence_items else 'No DAST evidence collected'

        # ── Evidence quality pre-check ──────────────────────────────
        all_failed    = all(not r['result'].get('success') for r in execution_results) \
                        if execution_results else True
        is_manifest   = finding.get('source') == 'manifest_analysis'
        tool_failures = [
            f"{r['tool']}: {r['result'].get('error', 'no data')}"
            for r in execution_results if not r['result'].get('success')
        ]

        # Manifest findings confirmed by manifest text alone — no DAST needed
        if is_manifest and all_failed:
            print(f'  [INFO] Manifest finding — confirming from SAST data (all DAST tools failed)')
            return {
                'verdict':          'CONFIRMED',
                'confidence':       'HIGH',
                'explanation':      (
                    f'This is a manifest configuration finding. The AndroidManifest.xml '
                    f'contains {finding.get("description", finding["title"])}. '
                    f'Manifest attributes are facts — they do not require DAST confirmation. '
                    f'DAST tools failed but this does not affect the verdict.'
                ),
                'evidence_summary': f'SAST manifest analysis: {finding["description"]}',
                'fix_recommendation': f'Remove or disable the insecure manifest flag. See CWE {finding.get("cwe", "N/A")}.',
                'risk_score':       7 if finding['severity'] == 'HIGH' else
                                    9 if finding['severity'] == 'CRITICAL' else 4,
                'exploitability':   (
                    'Manifest flags take effect at install time. No special conditions needed. '
                    'Any attacker with device access can exploit this configuration.'
                ),
                'screenshots':      screenshots
            }

        # All tools failed and it is NOT a manifest finding → NEEDS_REVIEW
        if all_failed and execution_results:
            print(f'  [INFO] All DAST tools failed — setting NEEDS_REVIEW')
            return {
                'verdict':          'NEEDS_REVIEW',
                'confidence':       'LOW',
                'explanation':      (
                    f'All DAST tools failed during validation. '
                    f'This does NOT mean the finding is a false positive — '
                    f'it means there is insufficient dynamic evidence to confirm or deny it. '
                    f'Tool failures: {"; ".join(tool_failures[:3])}'
                ),
                'evidence_summary': f'All tools failed: {", ".join(tool_failures[:3])}',
                'fix_recommendation': f'Manual review required. {finding.get("description", "")}',
                'risk_score':       5,
                'exploitability':   'Unknown — requires manual testing to determine exploitability.',
                'screenshots':      screenshots
            }
        # ── End pre-check — proceed to Groq for ambiguous cases ─────

        system_prompt = ANDROID_SECURITY_CONTEXT + """

Your task: analyze the DAST evidence and deliver a precise verdict on whether this SAST finding is real.

══════════════════════════════════════════════════
CRITICAL RULE — READ BEFORE ANYTHING ELSE:
If DAST tools failed, timed out, or returned errors →
verdict MUST be NEEDS_REVIEW with LOW confidence.
NEVER give FALSE_POSITIVE because tools failed.
Tool failure = insufficient evidence, NOT proof of safety.
Absence of evidence is NOT evidence of absence.
══════════════════════════════════════════════════

MANIFEST FINDINGS RULE:
For findings from source 'manifest_analysis' — the manifest
IS the evidence. If the finding description states that
android:debuggable=true, android:allowBackup=true,
android:exported=true, or similar flags are SET in the
AndroidManifest.xml — this is CONFIRMED regardless of DAST.
These are configuration facts, not code paths.
You do NOT need DAST to confirm a manifest attribute exists.

VERDICT RULES:
- CONFIRMED:      DAST evidence actively supports the finding,
                  OR it is a manifest/config fact
- FALSE_POSITIVE: You have POSITIVE evidence the code path is
                  unreachable, guarded, library-only, or test-only
- NEEDS_REVIEW:   Evidence is ambiguous, tools failed, or finding
                  requires manual testing to confirm

CONFIDENCE RULES:
- HIGH:   Clear definitive evidence for/against
- MEDIUM: Some evidence but not conclusive
- LOW:    Tools failed or no useful data collected — always
          pair LOW confidence with NEEDS_REVIEW verdict

RISK SCORE RULES (0-10):
- 9-10: Actively exploitable, no user interaction, RCE/data theft
- 7-8:  Exploitable with some conditions, significant data exposure
- 5-6:  Requires specific conditions, limited impact
- 3-4:  Theoretical risk, hard to exploit in practice
- 1-2:  Informational / best practice violation only

You MUST respond with ONLY valid JSON - no markdown, no explanation.
"""

        user_message = f"""
ORIGINAL SAST FINDING:
  Title:       {finding['title']}
  Severity:    {finding['severity']}
  CWE:         {finding['cwe']}
  OWASP:       {finding['owasp']}
  Source:      {source}
  Description: {finding['description']}

SPECIFIC FOCUS FOR THIS FINDING TYPE:
{src_context}

WHAT WE WERE LOOKING FOR:
{test_plan.get('what_to_look_for', 'N/A')}

FALSE POSITIVE INDICATORS:
{test_plan.get('false_positive_indicators', 'N/A')}

SEVERITY JUSTIFICATION:
{test_plan.get('severity_justification', 'N/A')}

DAST EVIDENCE COLLECTED:
{evidence_str}

Based on ALL of the above, give your verdict.
Be accurate. NEEDS_REVIEW is the correct answer when evidence is insufficient.
FALSE_POSITIVE requires positive proof the finding is wrong — not just failed tools.
CONFIRMED is appropriate for manifest/config facts even without successful DAST.
Respond with ONLY this JSON (raw, no markdown):

{{
  "verdict": "CONFIRMED",
  "confidence": "HIGH",
  "explanation": "2-3 precise sentences explaining WHY this verdict - cite specific evidence or lack thereof",
  "evidence_summary": "what specific evidence confirmed or denied this finding",
  "fix_recommendation": "concrete actionable fix for this specific issue in Android",
  "risk_score": 7,
  "exploitability": "how an attacker would actually exploit this in the real world"
}}
"""

        response = self.ask_groq(system_prompt, user_message)

        if not response:
            return self._default_verdict(finding)

        try:
            clean = response.strip()
            if '```' in clean:
                parts = clean.split('```')
                for part in parts:
                    if part.strip().startswith('{'):
                        clean = part.strip()
                        break
                else:
                    clean = parts[1]
                    if clean.startswith('json'):
                        clean = clean[4:]

            start = clean.find('{')
            end   = clean.rfind('}') + 1
            if start != -1 and end > start:
                clean = clean[start:end]
            verdict              = json.loads(clean)
            verdict['screenshots'] = screenshots
            return verdict

        except Exception as e:
            print(f'  [WARN] Could not parse verdict JSON: {e}')
            return self._default_verdict(finding)

    # -----------------------------------------
    # FULL VALIDATION PIPELINE
    # -----------------------------------------

    def validate_finding(self, finding, source_code_snippet=None):
        print(f'\n{"="*55}')
        print(f'  [{finding["severity"]}] {finding["title"][:50]}')
        print(f'  Source: {finding.get("source", "unknown")} | CWE: {finding.get("cwe", "N/A")}')
        print(f'{"="*55}')

        test_plan         = self.get_test_plan(finding, source_code_snippet)
        execution_results = self.execute_test_plan(test_plan, finding['id'])
        verdict           = self.get_verdict(finding, test_plan, execution_results)

        print(f'\n  [RESULT] {verdict["verdict"]} (Confidence: {verdict["confidence"]}) | Risk: {verdict.get("risk_score", "?")}/10')
        print(f'  {verdict["explanation"][:100]}')

        return {
            'finding':   finding,
            'test_plan': test_plan,
            'execution': execution_results,
            'verdict':   verdict
        }

    # -----------------------------------------
    # DEFAULTS (when API fails)
    # -----------------------------------------

    def _default_test_plan(self, finding):
        return {
            'test_plan': [
                {'step': 1, 'tool': 'launch_app',      'params': {'package': self.package}, 'reason': 'Launch app for basic validation'},
                {'step': 2, 'tool': 'take_screenshot',  'params': {'step': 1},               'reason': 'Capture app state'}
            ],
            'what_to_look_for':          'General app behavior and error states',
            'false_positive_indicators': 'Groq API unavailable - manual review required',
            'severity_justification':    'Could not assess - Groq API unavailable'
        }

    def _default_verdict(self, finding):
        return {
            'verdict':          'NEEDS_REVIEW',
            'confidence':       'LOW',
            'explanation':      'Groq API unavailable. Manual review required for this finding.',
            'evidence_summary': 'No AI analysis performed - API error',
            'fix_recommendation': f'Manually review: {finding.get("description", "")}',
            'risk_score':       5,
            'exploitability':   'Unknown - requires manual assessment',
            'screenshots':      []
        }