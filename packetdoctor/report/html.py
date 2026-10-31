"""Self-contained HTML report: one file, no network access, opens anywhere.

The report data is embedded as JSON in a non-executable <script> block and
drawn by the same renderer the dashboard uses. A meta Content-Security-Policy
forbids loading anything from the network.
"""

from __future__ import annotations

import html
import json
from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "web" / "static"

CSP = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:"


def _json_for_script(report: dict) -> str:
    text = json.dumps(report, default=str)
    # make it impossible to close the <script> element from inside the data
    return (
        text.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
        .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    )


def render_html(report: dict) -> str:
    css = (STATIC / "style.css").read_text(encoding="utf-8")
    js = (STATIC / "report.js").read_text(encoding="utf-8").replace("</", "<\\/")
    title = html.escape(f"PacketDoctor report - {report.get('capture', {}).get('file_name', 'capture')}")
    return "".join(
        [
            '<!doctype html><html lang="en"><head><meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            f'<meta http-equiv="Content-Security-Policy" content="{CSP}">',
            f"<title>{title}</title><style>{css}</style></head>",
            '<body class="standalone">',
            '<header class="topbar"><div class="brand"><span class="logo">+</span><div><h1>PacketDoctor</h1>',
            '<p class="tagline">Offline network diagnosis report</p></div></div></header>',
            '<main><section id="report"></section></main>',
            f'<script type="application/json" id="report-data">{_json_for_script(report)}</script>',
            f"<script>{js}\nPacketDoctor.renderReport(JSON.parse(document.getElementById('report-data').textContent), document.getElementById('report'));</script>",
            "</body></html>",
        ]
    )
