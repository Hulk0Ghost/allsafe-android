"""
Report Generator
Creates beautiful HTML report with findings,
verdicts, screenshots and fix recommendations
"""

import json
import os
import sys
import base64
from datetime import datetime


# ─────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────

OUTPUT_DIR   = os.getenv('OUTPUT_DIR', 'validation_output')
PACKAGE_NAME = os.getenv('PACKAGE_NAME', 'infosecadventures.allsafe')

RESULTS_JSON = sys.argv[1] if len(sys.argv) > 1 else \
               f'{OUTPUT_DIR}/validation_results.json'


# ─────────────────────────────────────────
# LOAD SCREENSHOT AS BASE64
# ─────────────────────────────────────────

def load_screenshot_b64(path):
    """Embed screenshot directly in HTML as base64"""
    try:
        if path and os.path.exists(path):
            with open(path, 'rb') as f:
                data = base64.b64encode(f.read()).decode('utf-8')
            return f'data:image/png;base64,{data}'
    except Exception:
        pass
    return None


# ─────────────────────────────────────────
# SEVERITY COLOR MAPPING
# ─────────────────────────────────────────

SEVERITY_COLORS = {
    'CRITICAL': {'bg': '#ffeaea', 'border': '#d32f2f',
                 'badge': '#d32f2f', 'text': '#b71c1c'},
    'HIGH':     {'bg': '#fff3e0', 'border': '#f57c00',
                 'badge': '#f57c00', 'text': '#e65100'},
    'MEDIUM':   {'bg': '#fffde7', 'border': '#f9a825',
                 'badge': '#f9a825', 'text': '#f57f17'},
}

VERDICT_COLORS = {
    'CONFIRMED':      {'bg': '#fdecea', 'color': '#c62828',
                       'icon': '🚨', 'label': 'Confirmed Vulnerability'},
    'FALSE_POSITIVE': {'bg': '#e8f5e9', 'color': '#2e7d32',
                       'icon': '✅', 'label': 'False Positive'},
    'NEEDS_REVIEW':   {'bg': '#e3f2fd', 'color': '#1565c0',
                       'icon': '🔵', 'label': 'Needs Manual Review'},
}


# ─────────────────────────────────────────
# GENERATE HTML
# ─────────────────────────────────────────

def generate_report(results):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Stats
    total      = len(results)
    critical   = sum(1 for r in results if r['severity'] == 'CRITICAL')
    high       = sum(1 for r in results if r['severity'] == 'HIGH')
    medium     = sum(1 for r in results if r['severity'] == 'MEDIUM')
    confirmed  = sum(1 for r in results if r['verdict'] == 'CONFIRMED')
    false_pos  = sum(1 for r in results if r['verdict'] == 'FALSE_POSITIVE')
    needs_rev  = sum(1 for r in results if r['verdict'] == 'NEEDS_REVIEW')

    # Overall risk score
    risk_scores = [r.get('risk_score', 0) for r in results
                   if r['verdict'] == 'CONFIRMED']
    avg_risk    = round(sum(risk_scores) / len(risk_scores), 1) \
                  if risk_scores else 0

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MobSF AI Validation Report</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont,
                         'Segoe UI', Roboto, sans-serif;
            background: #f0f2f5;
            color: #333;
        }}

        /* ── HEADER ── */
        .header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: white;
            padding: 40px;
        }}
        .header-top {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            flex-wrap: wrap;
            gap: 20px;
        }}
        .header h1 {{
            font-size: 26px;
            font-weight: 700;
            margin-bottom: 6px;
        }}
        .header p {{
            color: #8892b0;
            font-size: 14px;
        }}
        .risk-badge {{
            background: {'#d32f2f' if avg_risk >= 7
                         else '#f57c00' if avg_risk >= 4
                         else '#388e3c'};
            color: white;
            padding: 12px 24px;
            border-radius: 8px;
            text-align: center;
        }}
        .risk-badge .risk-num {{
            font-size: 36px;
            font-weight: 700;
            line-height: 1;
        }}
        .risk-badge .risk-label {{
            font-size: 12px;
            margin-top: 4px;
            opacity: 0.9;
        }}

        /* ── STATS ── */
        .stats {{
            display: flex;
            gap: 16px;
            padding: 24px 40px;
            flex-wrap: wrap;
            background: white;
            border-bottom: 1px solid #e0e0e0;
        }}
        .stat {{
            flex: 1;
            min-width: 110px;
            text-align: center;
            padding: 16px;
            border-radius: 8px;
            background: #f8f9fa;
        }}
        .stat .num {{
            font-size: 32px;
            font-weight: 700;
            line-height: 1;
        }}
        .stat .lbl {{
            font-size: 12px;
            color: #666;
            margin-top: 6px;
        }}
        .stat.critical .num {{ color: #d32f2f; }}
        .stat.high     .num {{ color: #f57c00; }}
        .stat.medium   .num {{ color: #f9a825; }}
        .stat.confirmed .num {{ color: #c62828; }}
        .stat.fp        .num {{ color: #2e7d32; }}
        .stat.review    .num {{ color: #1565c0; }}

        /* ── FILTERS ── */
        .filters {{
            padding: 20px 40px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            align-items: center;
        }}
        .filter-label {{ font-size: 13px; color: #666; margin-right: 4px; }}
        .filter-btn {{
            padding: 6px 16px;
            border: 1px solid #ddd;
            border-radius: 20px;
            background: white;
            cursor: pointer;
            font-size: 13px;
            transition: all 0.2s;
        }}
        .filter-btn:hover, .filter-btn.active {{
            background: #1a1a2e;
            color: white;
            border-color: #1a1a2e;
        }}

        /* ── FINDINGS ── */
        .findings {{ padding: 0 40px 40px; }}

        .finding-card {{
            background: white;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            overflow: hidden;
            transition: box-shadow 0.2s;
        }}
        .finding-card:hover {{
            box-shadow: 0 4px 16px rgba(0,0,0,0.12);
        }}

        .finding-header {{
            padding: 18px 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 12px;
            cursor: pointer;
            user-select: none;
        }}

        .finding-header-left {{
            display: flex;
            align-items: center;
            gap: 12px;
            flex: 1;
        }}

        .badge {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 700;
            color: white;
            white-space: nowrap;
        }}

        .finding-title {{
            font-size: 15px;
            font-weight: 600;
        }}

        .finding-header-right {{
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .verdict-badge {{
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            white-space: nowrap;
        }}

        .chevron {{
            font-size: 12px;
            color: #999;
            transition: transform 0.3s;
        }}
        .chevron.open {{ transform: rotate(180deg); }}

        .finding-body {{
            display: none;
            border-top: 1px solid #f0f0f0;
        }}
        .finding-body.open {{ display: block; }}

        .finding-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 0;
        }}

        .info-section {{
            padding: 20px 24px;
            border-right: 1px solid #f0f0f0;
        }}
        .info-section:last-child {{ border-right: none; }}
        .info-section h3 {{
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: #999;
            margin-bottom: 14px;
        }}

        .info-table {{ width: 100%; }}
        .info-table tr td {{
            padding: 6px 0;
            font-size: 13px;
            vertical-align: top;
        }}
        .info-table tr td:first-child {{
            color: #666;
            width: 120px;
            font-weight: 500;
        }}

        .verdict-box {{
            padding: 20px 24px;
            border-top: 1px solid #f0f0f0;
        }}
        .verdict-box h3 {{
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: #999;
            margin-bottom: 14px;
        }}
        .verdict-content {{
            padding: 16px;
            border-radius: 8px;
            font-size: 14px;
            line-height: 1.6;
        }}
        .verdict-content p {{ margin-bottom: 8px; }}
        .verdict-content p:last-child {{ margin-bottom: 0; }}
        .verdict-content strong {{ display: inline-block; width: 120px;
                                   color: #555; }}

        .fix-box {{
            padding: 20px 24px;
            border-top: 1px solid #f0f0f0;
            background: #f8f9fa;
        }}
        .fix-box h3 {{
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: #999;
            margin-bottom: 10px;
        }}
        .fix-box p {{
            font-size: 14px;
            line-height: 1.6;
            color: #444;
        }}

        /* ── SCREENSHOTS ── */
        .screenshots {{
            padding: 20px 24px;
            border-top: 1px solid #f0f0f0;
        }}
        .screenshots h3 {{
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: #999;
            margin-bottom: 14px;
        }}
        .screenshot-grid {{
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
        }}
        .screenshot-item {{
            position: relative;
        }}
        .screenshot-item img {{
            width: 200px;
            height: auto;
            border: 1px solid #ddd;
            border-radius: 6px;
            cursor: pointer;
            transition: transform 0.2s;
        }}
        .screenshot-item img:hover {{
            transform: scale(1.02);
        }}
        .screenshot-caption {{
            font-size: 11px;
            color: #999;
            text-align: center;
            margin-top: 4px;
        }}

        /* ── LIGHTBOX ── */
        .lightbox {{
            display: none;
            position: fixed;
            top: 0; left: 0;
            width: 100%; height: 100%;
            background: rgba(0,0,0,0.85);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }}
        .lightbox.open {{ display: flex; }}
        .lightbox img {{
            max-width: 90%;
            max-height: 90vh;
            border-radius: 8px;
        }}
        .lightbox-close {{
            position: fixed;
            top: 20px; right: 30px;
            color: white;
            font-size: 36px;
            cursor: pointer;
        }}

        /* ── FOOTER ── */
        .footer {{
            text-align: center;
            padding: 30px;
            color: #999;
            font-size: 12px;
            background: white;
            border-top: 1px solid #eee;
            margin-top: 20px;
        }}

        @media (max-width: 768px) {{
            .header, .stats, .filters, .findings {{ padding-left: 16px;
                                                    padding-right: 16px; }}
            .finding-grid {{ grid-template-columns: 1fr; }}
            .info-section {{ border-right: none;
                             border-bottom: 1px solid #f0f0f0; }}
        }}
    </style>
</head>
<body>

<!-- LIGHTBOX -->
<div class="lightbox" id="lightbox" onclick="closeLightbox()">
    <span class="lightbox-close">×</span>
    <img id="lightbox-img" src="" alt="Screenshot">
</div>

<!-- HEADER -->
<div class="header">
    <div class="header-top">
        <div>
            <h1>📱 MobSF AI Security Validation Report</h1>
            <p>Package: {PACKAGE_NAME} &nbsp;|&nbsp; Generated: {timestamp}</p>
            <p style="margin-top:8px; color:#64ffda; font-size:13px;">
                Powered by Claude AI + MobSF DAST
            </p>
        </div>
        <div class="risk-badge">
            <div class="risk-num">{avg_risk}</div>
            <div class="risk-label">Avg Risk Score</div>
        </div>
    </div>
</div>

<!-- STATS -->
<div class="stats">
    <div class="stat critical">
        <div class="num">{critical}</div>
        <div class="lbl">Critical</div>
    </div>
    <div class="stat high">
        <div class="num">{high}</div>
        <div class="lbl">High</div>
    </div>
    <div class="stat medium">
        <div class="num">{medium}</div>
        <div class="lbl">Medium</div>
    </div>
    <div class="stat">
        <div class="num">{total}</div>
        <div class="lbl">Total</div>
    </div>
    <div class="stat confirmed">
        <div class="num">{confirmed}</div>
        <div class="lbl">Confirmed</div>
    </div>
    <div class="stat fp">
        <div class="num">{false_pos}</div>
        <div class="lbl">False Positive</div>
    </div>
    <div class="stat review">
        <div class="num">{needs_rev}</div>
        <div class="lbl">Needs Review</div>
    </div>
</div>

<!-- FILTERS -->
<div class="filters">
    <span class="filter-label">Filter by:</span>
    <button class="filter-btn active" onclick="filterFindings('all', this)">
        All ({total})
    </button>
    <button class="filter-btn" onclick="filterFindings('CONFIRMED', this)">
        🚨 Confirmed ({confirmed})
    </button>
    <button class="filter-btn" onclick="filterFindings('FALSE_POSITIVE', this)">
        ✅ False Positive ({false_pos})
    </button>
    <button class="filter-btn" onclick="filterFindings('NEEDS_REVIEW', this)">
        🔵 Needs Review ({needs_rev})
    </button>
    <button class="filter-btn" onclick="filterFindings('CRITICAL', this)">
        Critical ({critical})
    </button>
    <button class="filter-btn" onclick="filterFindings('HIGH', this)">
        High ({high})
    </button>
    <button class="filter-btn" onclick="filterFindings('MEDIUM', this)">
        Medium ({medium})
    </button>
</div>

<!-- FINDINGS -->
<div class="findings">
"""

    # Generate each finding card
    for i, result in enumerate(results):
        severity  = result.get('severity', 'MEDIUM')
        verdict   = result.get('verdict', 'NEEDS_REVIEW')
        sev_color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS['MEDIUM'])
        ver_color = VERDICT_COLORS.get(verdict, VERDICT_COLORS['NEEDS_REVIEW'])

        # Load screenshots
        screenshot_html = ''
        screenshots     = result.get('screenshots', [])
        if screenshots:
            screenshot_html = '<div class="screenshots"><h3>📸 Screenshots</h3>'
            screenshot_html += '<div class="screenshot-grid">'
            for j, ss_path in enumerate(screenshots):
                b64 = load_screenshot_b64(ss_path)
                if b64:
                    name = os.path.basename(ss_path)
                    screenshot_html += f'''
                    <div class="screenshot-item">
                        <img src="{b64}" alt="Screenshot {j+1}"
                             onclick="openLightbox(this)">
                        <div class="screenshot-caption">{name}</div>
                    </div>'''
            screenshot_html += '</div></div>'

        html += f"""
    <div class="finding-card"
         data-verdict="{verdict}"
         data-severity="{severity}">

        <!-- Card Header -->
        <div class="finding-header"
             style="background:{sev_color['bg']};
                    border-left:5px solid {sev_color['border']};"
             onclick="toggleCard(this)">
            <div class="finding-header-left">
                <span class="badge"
                      style="background:{sev_color['badge']}">
                    {severity}
                </span>
                <span class="finding-title">
                    {result.get('title', 'Unknown Finding')[:80]}
                </span>
            </div>
            <div class="finding-header-right">
                <span class="verdict-badge"
                      style="background:{ver_color['bg']};
                             color:{ver_color['color']};">
                    {ver_color['icon']} {ver_color['label']}
                </span>
                <span class="risk-score"
                      style="font-size:12px; color:#666;">
                    Risk: {result.get('risk_score', 0)}/10
                </span>
                <span class="chevron">▼</span>
            </div>
        </div>

        <!-- Card Body -->
        <div class="finding-body">

            <!-- Info Grid -->
            <div class="finding-grid">
                <div class="info-section">
                    <h3>Finding Details</h3>
                    <table class="info-table">
                        <tr>
                            <td>ID</td>
                            <td>{result.get('finding_id', 'N/A')}</td>
                        </tr>
                        <tr>
                            <td>Severity</td>
                            <td><strong style="color:{sev_color['text']}">
                                {severity}</strong></td>
                        </tr>
                        <tr>
                            <td>CWE</td>
                            <td>{result.get('cwe', 'N/A')}</td>
                        </tr>
                        <tr>
                            <td>OWASP</td>
                            <td>{result.get('owasp', 'N/A')}</td>
                        </tr>
                        <tr>
                            <td>CVSS</td>
                            <td>{result.get('cvss', 'N/A')}</td>
                        </tr>
                    </table>
                </div>

                <div class="info-section">
                    <h3>AI Verdict</h3>
                    <table class="info-table">
                        <tr>
                            <td>Verdict</td>
                            <td><strong style="color:{ver_color['color']}">
                                {ver_color['icon']} {verdict}</strong></td>
                        </tr>
                        <tr>
                            <td>Confidence</td>
                            <td>{result.get('confidence', 'N/A')}</td>
                        </tr>
                        <tr>
                            <td>Risk Score</td>
                            <td><strong>{result.get('risk_score', 0)}/10
                                </strong></td>
                        </tr>
                    </table>
                </div>
            </div>

            <!-- Verdict Explanation -->
            <div class="verdict-box">
                <h3>🧠 Claude AI Analysis</h3>
                <div class="verdict-content"
                     style="background:{ver_color['bg']};
                            color:{ver_color['color']}">
                    <p><strong>Explanation:</strong>
                       {result.get('explanation', 'N/A')}</p>
                    <p><strong>Evidence:</strong>
                       {result.get('evidence_summary', 'N/A')}</p>
                </div>
            </div>

            <!-- Fix Recommendation -->
            <div class="fix-box">
                <h3>🔧 Fix Recommendation</h3>
                <p>{result.get('fix', 'No fix recommendation available.')}</p>
            </div>

            {screenshot_html}

        </div>
    </div>
"""

    html += f"""
</div>

<!-- FOOTER -->
<div class="footer">
    MobSF AI Security Validation Report &nbsp;|&nbsp;
    Claude AI + MobSF DAST &nbsp;|&nbsp;
    {timestamp}
</div>

<script>
    // Toggle card open/close
    function toggleCard(header) {{
        const body    = header.nextElementSibling;
        const chevron = header.querySelector('.chevron');
        body.classList.toggle('open');
        chevron.classList.toggle('open');
    }}

    // Filter findings
    function filterFindings(filter, btn) {{
        // Update active button
        document.querySelectorAll('.filter-btn').forEach(b => {{
            b.classList.remove('active');
        }});
        btn.classList.add('active');

        // Show/hide cards
        document.querySelectorAll('.finding-card').forEach(card => {{
            if (filter === 'all') {{
                card.style.display = 'block';
            }} else if (['CONFIRMED','FALSE_POSITIVE','NEEDS_REVIEW']
                        .includes(filter)) {{
                card.style.display =
                    card.dataset.verdict === filter ? 'block' : 'none';
            }} else {{
                card.style.display =
                    card.dataset.severity === filter ? 'block' : 'none';
            }}
        }});
    }}

    // Lightbox
    function openLightbox(img) {{
        document.getElementById('lightbox-img').src = img.src;
        document.getElementById('lightbox').classList.add('open');
        event.stopPropagation();
    }}

    function closeLightbox() {{
        document.getElementById('lightbox').classList.remove('open');
    }}

    document.addEventListener('keydown', function(e) {{
        if (e.key === 'Escape') closeLightbox();
    }});
</script>

</body>
</html>"""

    # Save report
    report_path = f'{OUTPUT_DIR}/validation_report.html'
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html)

    print(f'✅ HTML Report saved: {report_path}')
    return report_path


# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────

if __name__ == '__main__':
    print('\n' + '='*55)
    print('  Generating Validation Report')
    print('='*55)

    if not os.path.exists(RESULTS_JSON):
        print(f'❌ Results file not found: {RESULTS_JSON}')
        sys.exit(1)

    with open(RESULTS_JSON) as f:
        results = json.load(f)

    print(f'📊 Loaded {len(results)} validated findings')

    report_path = generate_report(results)

    print(f'\n✅ Report ready: {report_path}')
    print('   Open in browser to view!')
    sys.exit(0)