# -*- coding: utf-8 -*-
"""
HTML Report Generator for MobSF AI Validation Results
Generates a beautiful, interactive HTML report
"""

import json
import os
import sys
import base64
from datetime import datetime

# Fix Windows encoding
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# -----------------------------------------
# CONFIG
# -----------------------------------------

RESULTS_JSON = sys.argv[1] if len(sys.argv) > 1 else 'validation_results.json'
OUTPUT_DIR   = os.getenv('OUTPUT_DIR', 'validation_output')
PACKAGE_NAME = os.getenv('PACKAGE_NAME', 'Unknown App')

os.makedirs(OUTPUT_DIR, exist_ok=True)

# -----------------------------------------
# LOAD RESULTS
# -----------------------------------------

def load_results():
    print('[*] Loading validation results...')
    try:
        with open(RESULTS_JSON, encoding='utf-8') as f:
            data = json.load(f)
        print(f'  [OK] Loaded {len(data)} findings')
        return data
    except FileNotFoundError:
        print(f'[ERROR] Results file not found: {RESULTS_JSON}')
        sys.exit(1)
    except Exception as e:
        print(f'[ERROR] Failed to load results: {e}')
        sys.exit(1)

# -----------------------------------------
# ENCODE SCREENSHOTS
# -----------------------------------------

def encode_screenshot(path):
    try:
        if path and os.path.exists(path):
            with open(path, 'rb') as f:
                return base64.b64encode(f.read()).decode('utf-8')
    except Exception:
        pass
    return None

# -----------------------------------------
# STATS
# -----------------------------------------

def get_stats(results):
    stats = {
        'total':       len(results),
        'critical':    sum(1 for r in results if r.get('severity') == 'CRITICAL'),
        'high':        sum(1 for r in results if r.get('severity') == 'HIGH'),
        'medium':      sum(1 for r in results if r.get('severity') == 'MEDIUM'),
        'confirmed':   sum(1 for r in results if r.get('verdict') == 'CONFIRMED'),
        'false_pos':   sum(1 for r in results if r.get('verdict') == 'FALSE_POSITIVE'),
        'needs_rev':   sum(1 for r in results if r.get('verdict') == 'NEEDS_REVIEW'),
        'avg_risk':    0,
    }
    if results:
        scores = [r.get('risk_score', 0) for r in results]
        stats['avg_risk'] = round(sum(scores) / len(scores), 1)
    return stats

# -----------------------------------------
# SEVERITY / VERDICT COLORS
# -----------------------------------------

SEV_COLOR = {
    'CRITICAL': '#c62828',
    'HIGH':     '#e65100',
    'MEDIUM':   '#f9a825',
    'LOW':      '#2e7d32',
    'INFO':     '#1565c0',
}

VRD_COLOR = {
    'CONFIRMED':      '#c62828',
    'FALSE_POSITIVE': '#2e7d32',
    'NEEDS_REVIEW':   '#1565c0',
}

VRD_BG = {
    'CONFIRMED':      '#ffebee',
    'FALSE_POSITIVE': '#e8f5e9',
    'NEEDS_REVIEW':   '#e3f2fd',
}

# -----------------------------------------
# GENERATE HTML
# -----------------------------------------

def generate_html(results, stats):
    print('[*] Generating HTML report...')

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Build finding cards
    cards_html = ''
    for i, r in enumerate(results):
        sev     = r.get('severity', 'INFO')
        vrd     = r.get('verdict', 'NEEDS_REVIEW')
        sc_col  = SEV_COLOR.get(sev, '#888')
        vrd_col = VRD_COLOR.get(vrd, '#888')
        vrd_bg  = VRD_BG.get(vrd, '#f5f5f5')

        # Screenshots
        shots_html = ''
        for shot_path in r.get('screenshots', []):
            b64 = encode_screenshot(shot_path)
            if b64:
                shots_html += f'''
                <div class="screenshot-wrap">
                    <img src="data:image/png;base64,{b64}"
                         alt="Screenshot"
                         onclick="openLightbox(this.src)"
                         class="screenshot" />
                </div>'''

        if shots_html:
            shots_html = f'<div class="screenshots"><h4>Screenshots</h4><div class="shots-grid">{shots_html}</div></div>'

        risk_score = r.get('risk_score', 0)
        risk_color = '#c62828' if risk_score >= 8 else '#e65100' if risk_score >= 5 else '#2e7d32'

        cards_html += f'''
        <div class="card"
             data-severity="{sev}"
             data-verdict="{vrd}"
             style="border-left: 5px solid {sc_col}; background: {vrd_bg};">

            <div class="card-header" onclick="toggleCard(this)">
                <div class="card-title">
                    <span class="badge" style="background:{sc_col}">{sev}</span>
                    <span class="badge" style="background:{vrd_col}">{vrd}</span>
                    <span class="title-text">{r.get('title','Unknown')[:80]}</span>
                </div>
                <div class="card-meta">
                    <span class="risk-score" style="color:{risk_color}">
                        Risk: {risk_score}/10
                    </span>
                    <span class="confidence">
                        Confidence: {r.get('confidence','N/A')}
                    </span>
                    <span class="chevron">&#9660;</span>
                </div>
            </div>

            <div class="card-body" style="display:none;">
                <div class="info-grid">
                    <div class="info-item">
                        <label>CWE</label>
                        <span>{r.get('cwe','N/A')}</span>
                    </div>
                    <div class="info-item">
                        <label>OWASP</label>
                        <span>{r.get('owasp','N/A')}</span>
                    </div>
                    <div class="info-item">
                        <label>CVSS</label>
                        <span>{r.get('cvss', 'N/A')}</span>
                    </div>
                    <div class="info-item">
                        <label>Finding ID</label>
                        <span>{r.get('finding_id','N/A')[:40]}</span>
                    </div>
                </div>

                <div class="section">
                    <h4>AI Verdict</h4>
                    <p>{r.get('explanation','No explanation available.')}</p>
                </div>

                <div class="section">
                    <h4>Evidence Summary</h4>
                    <p>{r.get('evidence_summary','No evidence summary.')}</p>
                </div>

                <div class="section fix-box">
                    <h4>Fix Recommendation</h4>
                    <p>{r.get('fix','No fix recommendation.')}</p>
                </div>

                {shots_html}
            </div>
        </div>'''

    # Risk badge color for header
    avg = stats['avg_risk']
    avg_col = '#c62828' if avg >= 7 else '#e65100' if avg >= 4 else '#2e7d32'

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MobSF AI Validation Report - {PACKAGE_NAME}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI",
                         Roboto, Arial, sans-serif;
            background: #f0f2f5;
            color: #333;
            min-height: 100vh;
        }}

        /* HEADER */
        .header {{
            background: linear-gradient(135deg, #1a237e 0%, #283593 100%);
            color: white;
            padding: 30px 40px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        }}
        .header h1 {{ font-size: 28px; font-weight: 700; margin-bottom: 6px; }}
        .header .meta {{ font-size: 14px; opacity: 0.8; margin-bottom: 16px; }}
        .header .avg-risk {{
            display: inline-block;
            background: {avg_col};
            color: white;
            padding: 6px 16px;
            border-radius: 20px;
            font-weight: 700;
            font-size: 16px;
        }}

        /* STATS CARDS */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 16px;
            padding: 24px 40px;
        }}
        .stat-card {{
            background: white;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }}
        .stat-card .num {{
            font-size: 36px;
            font-weight: 800;
            line-height: 1;
            margin-bottom: 6px;
        }}
        .stat-card .lbl {{ font-size: 12px; color: #666; text-transform: uppercase; }}
        .stat-card.critical .num {{ color: #c62828; }}
        .stat-card.high     .num {{ color: #e65100; }}
        .stat-card.medium   .num {{ color: #f9a825; }}
        .stat-card.confirmed .num {{ color: #c62828; }}
        .stat-card.fp        .num {{ color: #2e7d32; }}
        .stat-card.review    .num {{ color: #1565c0; }}
        .stat-card.total     .num {{ color: #333; }}

        /* FILTERS */
        .filters {{
            padding: 0 40px 20px;
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            align-items: center;
        }}
        .filters span {{ font-weight: 600; margin-right: 6px; color: #555; }}
        .filter-btn {{
            padding: 7px 16px;
            border: 2px solid #ddd;
            background: white;
            border-radius: 20px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
            transition: all 0.2s;
        }}
        .filter-btn:hover,
        .filter-btn.active {{
            background: #1a237e;
            color: white;
            border-color: #1a237e;
        }}

        /* FINDINGS */
        .findings {{ padding: 0 40px 40px; }}
        .findings-count {{
            font-size: 13px;
            color: #666;
            margin-bottom: 16px;
        }}

        .card {{
            background: white;
            border-radius: 10px;
            margin-bottom: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.07);
            overflow: hidden;
            transition: box-shadow 0.2s;
        }}
        .card:hover {{ box-shadow: 0 4px 16px rgba(0,0,0,0.12); }}

        .card-header {{
            padding: 16px 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
        }}
        .card-title {{
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }}
        .title-text {{
            font-weight: 600;
            font-size: 14px;
        }}
        .badge {{
            color: white;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            white-space: nowrap;
        }}
        .card-meta {{
            display: flex;
            align-items: center;
            gap: 16px;
            font-size: 13px;
        }}
        .risk-score {{ font-weight: 800; font-size: 14px; }}
        .confidence {{ color: #666; }}
        .chevron {{ color: #999; font-size: 12px; }}

        .card-body {{
            padding: 20px;
            border-top: 1px solid #eee;
        }}

        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 12px;
            margin-bottom: 20px;
            background: #f8f9fa;
            padding: 14px;
            border-radius: 8px;
        }}
        .info-item label {{
            display: block;
            font-size: 11px;
            text-transform: uppercase;
            color: #888;
            margin-bottom: 3px;
            font-weight: 600;
        }}
        .info-item span {{
            font-size: 13px;
            font-weight: 600;
            color: #333;
        }}

        .section {{ margin-bottom: 16px; }}
        .section h4 {{
            font-size: 13px;
            text-transform: uppercase;
            color: #555;
            margin-bottom: 6px;
            font-weight: 700;
        }}
        .section p {{
            font-size: 14px;
            line-height: 1.6;
            color: #444;
        }}
        .fix-box {{
            background: #e8f5e9;
            border-left: 4px solid #2e7d32;
            padding: 12px 16px;
            border-radius: 0 8px 8px 0;
        }}
        .fix-box h4 {{ color: #2e7d32; }}

        /* SCREENSHOTS */
        .screenshots {{ margin-top: 16px; }}
        .screenshots h4 {{
            font-size: 13px;
            text-transform: uppercase;
            color: #555;
            margin-bottom: 10px;
            font-weight: 700;
        }}
        .shots-grid {{
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }}
        .screenshot-wrap {{
            border: 2px solid #ddd;
            border-radius: 8px;
            overflow: hidden;
            cursor: pointer;
        }}
        .screenshot {{
            max-width: 200px;
            max-height: 360px;
            display: block;
            transition: transform 0.2s;
        }}
        .screenshot:hover {{ transform: scale(1.02); }}

        /* LIGHTBOX */
        .lightbox {{
            display: none;
            position: fixed;
            top: 0; left: 0;
            width: 100%; height: 100%;
            background: rgba(0,0,0,0.9);
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
            position: absolute;
            top: 20px; right: 30px;
            color: white;
            font-size: 36px;
            cursor: pointer;
            font-weight: bold;
        }}

        /* NO RESULTS */
        .no-results {{
            text-align: center;
            padding: 60px;
            color: #999;
            font-size: 18px;
        }}

        @media (max-width: 600px) {{
            .header, .stats-grid, .filters, .findings {{
                padding-left: 16px;
                padding-right: 16px;
            }}
        }}
    </style>
</head>
<body>

<!-- HEADER -->
<div class="header">
    <h1>MobSF AI Validation Report</h1>
    <div class="meta">
        Package: <strong>{PACKAGE_NAME}</strong> &nbsp;|&nbsp;
        Generated: {timestamp} &nbsp;|&nbsp;
        Total Findings: {stats['total']}
    </div>
    <div class="avg-risk">Average Risk Score: {stats['avg_risk']}/10</div>
</div>

<!-- STATS -->
<div class="stats-grid">
    <div class="stat-card total">
        <div class="num">{stats['total']}</div>
        <div class="lbl">Total</div>
    </div>
    <div class="stat-card critical">
        <div class="num">{stats['critical']}</div>
        <div class="lbl">Critical</div>
    </div>
    <div class="stat-card high">
        <div class="num">{stats['high']}</div>
        <div class="lbl">High</div>
    </div>
    <div class="stat-card medium">
        <div class="num">{stats['medium']}</div>
        <div class="lbl">Medium</div>
    </div>
    <div class="stat-card confirmed">
        <div class="num">{stats['confirmed']}</div>
        <div class="lbl">Confirmed</div>
    </div>
    <div class="stat-card fp">
        <div class="num">{stats['false_pos']}</div>
        <div class="lbl">False Pos.</div>
    </div>
    <div class="stat-card review">
        <div class="num">{stats['needs_rev']}</div>
        <div class="lbl">Need Review</div>
    </div>
</div>

<!-- FILTERS -->
<div class="filters">
    <span>Filter:</span>
    <button class="filter-btn active" onclick="filterCards('ALL', this)">All</button>
    <button class="filter-btn" onclick="filterCards('CONFIRMED', this)">Confirmed</button>
    <button class="filter-btn" onclick="filterCards('FALSE_POSITIVE', this)">False Positives</button>
    <button class="filter-btn" onclick="filterCards('NEEDS_REVIEW', this)">Needs Review</button>
    <button class="filter-btn" onclick="filterCards('CRITICAL', this)">Critical</button>
    <button class="filter-btn" onclick="filterCards('HIGH', this)">High</button>
    <button class="filter-btn" onclick="filterCards('MEDIUM', this)">Medium</button>
</div>

<!-- FINDINGS -->
<div class="findings">
    <div class="findings-count" id="findings-count">
        Showing {stats['total']} of {stats['total']} findings
    </div>
    <div id="cards-container">
        {cards_html if cards_html else '<div class="no-results">No findings to display.</div>'}
    </div>
</div>

<!-- LIGHTBOX -->
<div class="lightbox" id="lightbox" onclick="closeLightbox()">
    <span class="lightbox-close">&times;</span>
    <img id="lightbox-img" src="" alt="Screenshot" onclick="event.stopPropagation()">
</div>

<script>
    // Toggle card expand/collapse
    function toggleCard(header) {{
        var body = header.nextElementSibling;
        var chevron = header.querySelector('.chevron');
        if (body.style.display === 'none') {{
            body.style.display = 'block';
            chevron.innerHTML = '&#9650;';
        }} else {{
            body.style.display = 'none';
            chevron.innerHTML = '&#9660;';
        }}
    }}

    // Filter cards
    function filterCards(filter, btn) {{
        document.querySelectorAll('.filter-btn').forEach(function(b) {{
            b.classList.remove('active');
        }});
        btn.classList.add('active');

        var cards   = document.querySelectorAll('.card');
        var visible = 0;
        cards.forEach(function(card) {{
            var sev = card.getAttribute('data-severity');
            var vrd = card.getAttribute('data-verdict');
            var show = (filter === 'ALL') || (sev === filter) || (vrd === filter);
            card.style.display = show ? 'block' : 'none';
            if (show) visible++;
        }});

        var total = cards.length;
        document.getElementById('findings-count').textContent =
            'Showing ' + visible + ' of ' + total + ' findings';
    }}

    // Lightbox
    function openLightbox(src) {{
        document.getElementById('lightbox-img').src = src;
        document.getElementById('lightbox').classList.add('open');
    }}
    function closeLightbox() {{
        document.getElementById('lightbox').classList.remove('open');
    }}
    document.addEventListener('keydown', function(e) {{
        if (e.key === 'Escape') closeLightbox();
    }});
</script>
</body>
</html>'''

    return html

# -----------------------------------------
# SAVE REPORT
# -----------------------------------------

def save_report(html):
    report_path = os.path.join(OUTPUT_DIR, 'validation_report.html')
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f'  [OK] Report saved: {report_path}')
    return report_path

# -----------------------------------------
# MAIN
# -----------------------------------------

if __name__ == '__main__':
    print('\n' + '='*55)
    print('  Generating Validation Report')
    print('='*55)

    print(f'  Results file : {RESULTS_JSON}')
    print(f'  Output dir   : {OUTPUT_DIR}')
    print(f'  Package      : {PACKAGE_NAME}')

    results = load_results()
    stats   = get_stats(results)

    print(f'\n  Stats:')
    print(f'    Total     : {stats["total"]}')
    print(f'    Critical  : {stats["critical"]}')
    print(f'    High      : {stats["high"]}')
    print(f'    Medium    : {stats["medium"]}')
    print(f'    Confirmed : {stats["confirmed"]}')
    print(f'    False Pos : {stats["false_pos"]}')
    print(f'    Review    : {stats["needs_rev"]}')
    print(f'    Avg Risk  : {stats["avg_risk"]}/10')

    html = generate_html(results, stats)
    path = save_report(html)

    print(f'\n[OK] Report generation complete!')
    print(f'     Open in browser: {path}')
    print('='*55)
    sys.exit(0)