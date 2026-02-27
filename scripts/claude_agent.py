"""
Claude AI Agent
Decides how to validate each SAST finding using MobSF DAST tools
"""

import json
import requests
import os


class ClaudeAgent:

    def __init__(self, api_key, mobsf_tools, package_name):
        self.api_key      = api_key
        self.tools        = mobsf_tools
        self.package      = package_name
        self.model        = 'claude-sonnet-4-20250514'
        self.api_url      = 'https://api.anthropic.com/v1/messages'
        self.headers      = {
            'x-api-key':         api_key,
            'anthropic-version': '2023-06-01',
            'content-type':      'application/json'
        }

    # ─────────────────────────────────────────
    # CALL CLAUDE API
    # ─────────────────────────────────────────

    def ask_claude(self, system_prompt, user_message, max_tokens=2000):
        """Send message to Claude and get response"""
        try:
            payload = {
                'model':      self.model,
                'max_tokens': max_tokens,
                'system':     system_prompt,
                'messages': [
                    {'role': 'user', 'content': user_message}
                ]
            }
            r = requests.post(
                self.api_url,
                headers=self.headers,
                json=payload,
                timeout=60
            )
            response = r.json()

            if 'content' in response:
                return response['content'][0]['text']
            else:
                print(f'  ⚠️ Claude error: {response}')
                return None

        except Exception as e:
            print(f'  ⚠️ Claude API failed: {e}')
            return None

    # ─────────────────────────────────────────
    # STEP 1: CLAUDE DECIDES TEST PLAN
    # ─────────────────────────────────────────

    def get_test_plan(self, finding, source_code_snippet=None):
        """
        Ask Claude: given this SAST finding,
        what MobSF DAST steps should we run?
        """
        print(f'  🧠 Claude analyzing finding: {finding["title"][:50]}')

        tool_list = json.dumps(self.tools.get_tool_list(), indent=2)

        source_context = ''
        if source_code_snippet:
            source_context = f"""
RELEVANT SOURCE CODE:
{source_code_snippet}
"""

        system_prompt = """You are a mobile security expert and penetration tester.
Your job is to validate Android security findings found by static analysis (SAST).
You have access to a live Android emulator with MobSF DAST tools.

You must respond ONLY with valid JSON - no explanation, no markdown, no code blocks.
Just raw JSON."""

        user_message = f"""
SAST FINDING TO VALIDATE:
- ID: {finding['id']}
- Title: {finding['title']}
- Severity: {finding['severity']}
- CWE: {finding['cwe']}
- OWASP: {finding['owasp']}
- Description: {finding['description']}
- Affected Files: {json.dumps(list(finding['files'].keys())[:3])}

{source_context}

AVAILABLE MOBSF DAST TOOLS:
{tool_list}

APP PACKAGE: {self.package}

Based on this SAST finding, create a test plan to validate it dynamically.
Respond with this exact JSON structure:

{{
  "test_plan": [
    {{
      "step": 1,
      "tool": "tool_name_here",
      "params": {{"key": "value"}},
      "reason": "why this step"
    }}
  ],
  "what_to_look_for": "what evidence would confirm this finding",
  "false_positive_indicators": "what would indicate this is a false positive",
  "max_steps": 5
}}
"""

        response = self.ask_claude(system_prompt, user_message)

        if not response:
            return self._default_test_plan(finding)

        # Parse JSON from Claude
        try:
            # Clean response just in case
            clean = response.strip()
            if clean.startswith('```'):
                clean = clean.split('```')[1]
                if clean.startswith('json'):
                    clean = clean[4:]
            return json.loads(clean)
        except Exception as e:
            print(f'  ⚠️ Could not parse Claude test plan: {e}')
            return self._default_test_plan(finding)

    # ─────────────────────────────────────────
    # STEP 2: EXECUTE TEST PLAN
    # ─────────────────────────────────────────

    def execute_test_plan(self, test_plan, finding_id):
        """Execute the steps Claude planned"""
        print(f'  ⚙️ Executing {len(test_plan["test_plan"])} test steps...')
        results = []

        for step in test_plan['test_plan']:
            tool_name = step['tool']
            params    = step.get('params', {})
            reason    = step.get('reason', '')

            print(f'\n  Step {step["step"]}: {tool_name}')
            print(f'  Reason: {reason}')

            result = self._call_tool(tool_name, params, finding_id)
            results.append({
                'step':    step['step'],
                'tool':    tool_name,
                'params':  params,
                'reason':  reason,
                'result':  result
            })

        return results

    # ─────────────────────────────────────────
    # TOOL DISPATCHER
    # ─────────────────────────────────────────

    def _call_tool(self, tool_name, params, finding_id):
        """Call the right MobSF tool based on Claude's decision"""
        safe_id = finding_id.replace('/', '_').replace(' ', '_')

        dispatch = {
            'start_activity':           lambda: self.tools.start_activity(
                                            params.get('activity', '')),
            'launch_app':               lambda: self.tools.launch_app(
                                            params.get('package', self.package)),
            'stop_app':                 lambda: self.tools.stop_app(
                                            params.get('package', self.package)),
            'adb_input_text':           lambda: self.tools.adb_input_text(
                                            params.get('text', '')),
            'adb_tap':                  lambda: self.tools.adb_tap(
                                            params.get('x', 500),
                                            params.get('y', 500)),
            'adb_press_key':            lambda: self.tools.adb_press_key(
                                            params.get('keycode', 66)),
            'take_screenshot':          lambda: self.tools.take_screenshot(
                                            f'{safe_id}_step{params.get("step",1)}'),
            'start_pcap':               lambda: self.tools.start_pcap(),
            'stop_pcap':                lambda: self.tools.stop_pcap(),
            'get_http_logs':            lambda: self.tools.get_http_logs(),
            'get_frida_logs':           lambda: self.tools.get_frida_logs(),
            'run_frida_script':         lambda: self.tools.run_frida_script(),
            'get_logcat':               lambda: self.tools.get_logcat(),
            'test_exported_activities': lambda: self.tools.test_exported_activities(),
        }

        if tool_name in dispatch:
            try:
                return dispatch[tool_name]()
            except Exception as e:
                return {'success': False, 'error': str(e)}
        else:
            print(f'  ⚠️ Unknown tool: {tool_name}')
            return {'success': False, 'error': f'Unknown tool: {tool_name}'}

    # ─────────────────────────────────────────
    # STEP 3: CLAUDE GIVES VERDICT
    # ─────────────────────────────────────────

    def get_verdict(self, finding, test_plan, execution_results):
        """
        Ask Claude: given the test results,
        is this finding real or a false positive?
        """
        print(f'  🔍 Claude analyzing results...')

        # Build evidence summary for Claude
        evidence = []
        screenshots = []

        for r in execution_results:
            tool   = r['tool']
            result = r['result']

            if tool == 'take_screenshot' and result.get('success'):
                screenshots.append(result.get('path', ''))

            if tool == 'get_http_logs' and result.get('success'):
                data = result.get('data', {})
                evidence.append(f'HTTP Traffic captured: {json.dumps(data)[:500]}')

            if tool == 'get_frida_logs' and result.get('success'):
                data = result.get('data', {})
                evidence.append(f'Frida logs: {json.dumps(data)[:500]}')

            if tool == 'get_logcat' and result.get('success'):
                data = result.get('data', {})
                evidence.append(f'Logcat: {json.dumps(data)[:300]}')

            if result.get('success'):
                evidence.append(f'Tool {tool}: succeeded')
            else:
                evidence.append(f'Tool {tool}: failed - {result.get("error","")}')

        system_prompt = """You are a senior mobile security analyst.
Analyze the DAST test results and give a verdict on the SAST finding.
Respond ONLY with valid JSON - no explanation, no markdown, no code blocks."""

        user_message = f"""
ORIGINAL SAST FINDING:
- Title: {finding['title']}
- Severity: {finding['severity']}
- CWE: {finding['cwe']}
- Description: {finding['description']}

WHAT WE WERE LOOKING FOR:
{test_plan.get('what_to_look_for', 'N/A')}

FALSE POSITIVE INDICATORS:
{test_plan.get('false_positive_indicators', 'N/A')}

DAST TEST EVIDENCE:
{chr(10).join(evidence)}

Based on this evidence, respond with this exact JSON:

{{
  "verdict": "CONFIRMED" or "FALSE_POSITIVE" or "NEEDS_REVIEW",
  "confidence": "HIGH" or "MEDIUM" or "LOW",
  "explanation": "2-3 sentences explaining the verdict",
  "evidence_summary": "what evidence led to this verdict",
  "fix_recommendation": "how to fix this if real",
  "risk_score": 0-10
}}
"""

        response = self.ask_claude(system_prompt, user_message)

        if not response:
            return self._default_verdict(finding)

        try:
            clean = response.strip()
            if clean.startswith('```'):
                clean = clean.split('```')[1]
                if clean.startswith('json'):
                    clean = clean[4:]
            verdict = json.loads(clean)
            verdict['screenshots'] = screenshots
            return verdict
        except Exception as e:
            print(f'  ⚠️ Could not parse verdict: {e}')
            return self._default_verdict(finding)

    # ─────────────────────────────────────────
    # FULL VALIDATION (all 3 steps)
    # ─────────────────────────────────────────

    def validate_finding(self, finding, source_code_snippet=None):
        """Run full validation pipeline for one finding"""
        print(f'\n{"="*55}')
        print(f'  Validating: {finding["severity"]} - {finding["title"][:45]}')
        print(f'{"="*55}')

        # Step 1: Get test plan from Claude
        test_plan = self.get_test_plan(finding, source_code_snippet)
        print(f'  📋 Test plan: {len(test_plan["test_plan"])} steps')
        print(f'  🔍 Looking for: {test_plan.get("what_to_look_for", "")[:80]}')

        # Step 2: Execute test plan
        execution_results = self.execute_test_plan(test_plan, finding['id'])

        # Step 3: Get verdict from Claude
        verdict = self.get_verdict(finding, test_plan, execution_results)

        print(f'\n  📊 VERDICT: {verdict["verdict"]} '
              f'(Confidence: {verdict["confidence"]})')
        print(f'  💬 {verdict["explanation"][:100]}')

        return {
            'finding':   finding,
            'test_plan': test_plan,
            'execution': execution_results,
            'verdict':   verdict
        }

    # ─────────────────────────────────────────
    # DEFAULTS (if Claude API fails)
    # ─────────────────────────────────────────

    def _default_test_plan(self, finding):
        return {
            'test_plan': [
                {
                    'step':   1,
                    'tool':   'launch_app',
                    'params': {'package': self.package},
                    'reason': 'Launch app for basic validation'
                },
                {
                    'step':   2,
                    'tool':   'take_screenshot',
                    'params': {'step': 1},
                    'reason': 'Capture app state'
                }
            ],
            'what_to_look_for':          'General app behavior',
            'false_positive_indicators': 'Could not analyze - Claude API unavailable'
        }

    def _default_verdict(self, finding):
        return {
            'verdict':          'NEEDS_REVIEW',
            'confidence':       'LOW',
            'explanation':      'Could not get AI verdict - manual review required',
            'evidence_summary': 'Claude API unavailable',
            'fix_recommendation': 'Manual review required',
            'risk_score':       5,
            'screenshots':      []
        }