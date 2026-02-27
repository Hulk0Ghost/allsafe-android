"""
MobSF DAST API Wrapper
All MobSF tools Claude can use for validation
"""

import requests
import subprocess
import time
import os
import base64


class MobSFTools:

    def __init__(self, server, api_key, hash_val, output_dir='validation_output'):
        self.server     = server.rstrip('/')
        self.api_key    = api_key
        self.hash       = hash_val
        self.output_dir = output_dir
        self.headers    = {'Authorization': api_key}
        os.makedirs(f'{output_dir}/screenshots', exist_ok=True)
        os.makedirs(f'{output_dir}/pcap', exist_ok=True)
        os.makedirs(f'{output_dir}/logs', exist_ok=True)

    # ─────────────────────────────────────────
    # APP CONTROL
    # ─────────────────────────────────────────

    def start_activity(self, activity):
        """Launch a specific activity in the app"""
        print(f'  🚀 Starting activity: {activity}')
        try:
            r = requests.post(
                f'{self.server}/api/v1/android/start_activity',
                headers=self.headers,
                data={'hash': self.hash, 'activity': activity},
                timeout=30
            )
            time.sleep(3)
            return {'success': True, 'response': r.json()}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def launch_app(self, package):
        """Launch app via ADB monkey"""
        print(f'  📱 Launching app: {package}')
        try:
            subprocess.run([
                'adb', 'shell', 'monkey', '-p', package,
                '-c', 'android.intent.category.LAUNCHER', '1'
            ], timeout=15, capture_output=True)
            time.sleep(3)
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def stop_app(self, package):
        """Force stop the app"""
        print(f'  ⏹️ Stopping app: {package}')
        try:
            subprocess.run([
                'adb', 'shell', 'am', 'force-stop', package
            ], timeout=10, capture_output=True)
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # ─────────────────────────────────────────
    # ADB INPUT
    # ─────────────────────────────────────────

    def adb_input_text(self, text):
        """Type text into focused field"""
        print(f'  ⌨️ Inputting text: {text[:30]}...')
        try:
            # Escape special chars for ADB
            escaped = text.replace(' ', '%s').replace("'", "\\'")
            subprocess.run([
                'adb', 'shell', 'input', 'text', escaped
            ], timeout=10, capture_output=True)
            time.sleep(1)
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def adb_tap(self, x, y):
        """Tap on screen coordinates"""
        print(f'  👆 Tapping: ({x}, {y})')
        try:
            subprocess.run([
                'adb', 'shell', 'input', 'tap', str(x), str(y)
            ], timeout=10, capture_output=True)
            time.sleep(1)
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def adb_press_key(self, keycode):
        """Press a key (e.g. KEYCODE_ENTER=66)"""
        print(f'  🔑 Pressing key: {keycode}')
        try:
            subprocess.run([
                'adb', 'shell', 'input', 'keyevent', str(keycode)
            ], timeout=10, capture_output=True)
            time.sleep(1)
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # ─────────────────────────────────────────
    # SCREENSHOT
    # ─────────────────────────────────────────

    def take_screenshot(self, name):
        """Capture emulator screenshot"""
        print(f'  📸 Taking screenshot: {name}')
        try:
            # Try MobSF API first
            r = requests.post(
                f'{self.server}/api/v1/android/screenshot',
                headers=self.headers,
                data={'hash': self.hash},
                timeout=20
            )
            if r.status_code == 200 and r.headers.get('content-type', '').startswith('image'):
                path = f'{self.output_dir}/screenshots/{name}.png'
                with open(path, 'wb') as f:
                    f.write(r.content)
                print(f'  ✅ Screenshot saved: {path}')
                return {'success': True, 'path': path}
        except Exception:
            pass

        # Fallback to ADB
        try:
            subprocess.run([
                'adb', 'shell', 'screencap', '-p', f'/sdcard/{name}.png'
            ], timeout=10, capture_output=True)
            path = f'{self.output_dir}/screenshots/{name}.png'
            subprocess.run([
                'adb', 'pull', f'/sdcard/{name}.png', path
            ], timeout=10, capture_output=True)
            subprocess.run([
                'adb', 'shell', 'rm', f'/sdcard/{name}.png'
            ], timeout=5, capture_output=True)
            print(f'  ✅ Screenshot saved via ADB: {path}')
            return {'success': True, 'path': path}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # ─────────────────────────────────────────
    # NETWORK CAPTURE
    # ─────────────────────────────────────────

    def start_pcap(self):
        """Start network packet capture"""
        print('  🌐 Starting network capture...')
        try:
            r = requests.post(
                f'{self.server}/api/v1/android/start_pcap',
                headers=self.headers,
                data={'hash': self.hash},
                timeout=20
            )
            return {'success': True, 'response': r.json()}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def stop_pcap(self):
        """Stop network packet capture"""
        print('  🛑 Stopping network capture...')
        try:
            r = requests.post(
                f'{self.server}/api/v1/android/stop_pcap',
                headers=self.headers,
                data={'hash': self.hash},
                timeout=20
            )
            return {'success': True, 'response': r.json()}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_http_logs(self):
        """Get captured HTTP traffic"""
        print('  📡 Getting HTTP logs...')
        try:
            r = requests.post(
                f'{self.server}/api/v1/android/httptools',
                headers=self.headers,
                data={'hash': self.hash},
                timeout=20
            )
            data = r.json()
            # Save to file
            log_path = f'{self.output_dir}/logs/http_logs.json'
            with open(log_path, 'w') as f:
                import json
                json.dump(data, f, indent=2)
            return {'success': True, 'data': data, 'path': log_path}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # ─────────────────────────────────────────
    # FRIDA HOOKS
    # ─────────────────────────────────────────

    def get_frida_logs(self):
        """Get Frida instrumentation logs"""
        print('  🔬 Getting Frida logs...')
        try:
            r = requests.post(
                f'{self.server}/api/v1/android/frida_logs',
                headers=self.headers,
                data={'hash': self.hash},
                timeout=20
            )
            data = r.json()
            log_path = f'{self.output_dir}/logs/frida_logs.json'
            with open(log_path, 'w') as f:
                import json
                json.dump(data, f, indent=2)
            return {'success': True, 'data': data, 'path': log_path}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def run_frida_script(self, script_type='default'):
        """Run Frida instrumentation script"""
        print(f'  🔭 Running Frida script: {script_type}')
        try:
            r = requests.post(
                f'{self.server}/api/v1/android/frida_view',
                headers=self.headers,
                data={'hash': self.hash, 'default': 1},
                timeout=30
            )
            time.sleep(5)
            return {'success': True, 'response': r.json()}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # ─────────────────────────────────────────
    # LOGCAT
    # ─────────────────────────────────────────

    def get_logcat(self):
        """Get Android logcat output"""
        print('  📋 Getting logcat...')
        try:
            r = requests.post(
                f'{self.server}/api/v1/android/logcat',
                headers=self.headers,
                data={'hash': self.hash},
                timeout=20
            )
            data = r.json()
            log_path = f'{self.output_dir}/logs/logcat.json'
            with open(log_path, 'w') as f:
                import json
                json.dump(data, f, indent=2)
            return {'success': True, 'data': data, 'path': log_path}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # ─────────────────────────────────────────
    # EXPORTED COMPONENTS
    # ─────────────────────────────────────────

    def test_exported_activities(self):
        """Test all exported activities"""
        print('  📤 Testing exported activities...')
        try:
            r = requests.post(
                f'{self.server}/api/v1/android/activity',
                headers=self.headers,
                data={'hash': self.hash},
                timeout=30
            )
            return {'success': True, 'data': r.json()}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # ─────────────────────────────────────────
    # SUMMARY
    # ─────────────────────────────────────────

    def get_tool_list(self):
        """Return list of available tools for Claude"""
        return {
            'start_activity':         'Launch specific app activity by name',
            'launch_app':             'Launch app from home screen',
            'stop_app':               'Force stop the app',
            'adb_input_text':         'Type text into focused input field',
            'adb_tap':                'Tap on screen at x,y coordinates',
            'adb_press_key':          'Press Android key (66=Enter, 4=Back)',
            'take_screenshot':        'Capture emulator screenshot',
            'start_pcap':             'Start network packet capture',
            'stop_pcap':              'Stop network packet capture',
            'get_http_logs':          'Get all captured HTTP traffic',
            'get_frida_logs':         'Get Frida runtime hook logs',
            'run_frida_script':       'Run Frida instrumentation on app',
            'get_logcat':             'Get Android system logs',
            'test_exported_activities': 'Test all exported app activities',
        }