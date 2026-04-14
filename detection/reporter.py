# HTML report generator.
# Produces a self-contained single-file HTML detection report from a list
# of SuspiciousHost objects. All CSS and JS are inlined — no external requests.

from __future__ import annotations

import dataclasses
import html
import json
from datetime import datetime, timezone
from pathlib import Path

from detection.pcap_analyzer import SuspiciousHost

_CONFIDENCE_COLOURS = {
    "high":   "#f85149",
    "medium": "#d29922",
    "low":    "#8b949e",
}


def generate_report(
    results: list[SuspiciousHost],
    source_path: Path,
    output_path: Path | None = None,
) -> str:
    """Generate a self-contained HTML detection report.

    Renders each SuspiciousHost as a collapsible card with confidence badge,
    stats grid, signals list, and beacon timing summary.

    Args:
        results: Flagged domains from the analyzer, ordered by avg_entropy.
        source_path: Path to the PCAP or Zeek log that was analysed. Used
            as the source file label in the report header.
        output_path: If provided, the HTML string is written to this file.

    Returns:
        The complete HTML document as a string.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    source_name = html.escape(source_path.name)

    highest_confidence = "none"
    if results:
        order = {"high": 0, "medium": 1, "low": 2}
        highest_confidence = min(results, key=lambda h: order.get(h.confidence, 9)).confidence

    suspicious_count = len(results)

    # ── CSS ──────────────────────────────────────────────────────────────────
    css = """
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
        background: #0d1117;
        color: #e6edf3;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        font-size: 14px;
        line-height: 1.6;
        padding: 24px 16px 48px;
    }
    .container { max-width: 900px; margin: 0 auto; }
    .header {
        border-bottom: 1px solid #30363d;
        padding-bottom: 16px;
        margin-bottom: 24px;
    }
    .header h1 { font-size: 22px; font-weight: 600; margin-bottom: 4px; }
    .header .meta { color: #8b949e; font-size: 12px; }
    .summary {
        display: flex;
        gap: 16px;
        margin-bottom: 28px;
        flex-wrap: wrap;
    }
    .stat-box {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 6px;
        padding: 16px 24px;
        text-align: center;
        flex: 1 1 140px;
    }
    .stat-box .value { font-size: 28px; font-weight: 700; }
    .stat-box .label { font-size: 11px; color: #8b949e; text-transform: uppercase; letter-spacing: .05em; margin-top: 4px; }
    .no-results {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 6px;
        padding: 32px;
        text-align: center;
        color: #8b949e;
    }
    .card {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 6px;
        margin-bottom: 16px;
        overflow: hidden;
    }
    .card-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 14px 20px;
        cursor: pointer;
        user-select: none;
    }
    .card-header:hover { background: #1c2128; }
    .card-domain {
        font-family: 'Courier New', monospace;
        font-size: 15px;
        font-weight: 600;
    }
    .card-right { display: flex; align-items: center; gap: 12px; }
    .badge {
        border-radius: 12px;
        padding: 2px 10px;
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: .05em;
        color: #0d1117;
    }
    .toggle { color: #8b949e; font-size: 18px; transition: transform .2s; }
    .card-body { padding: 0 20px 20px; }
    .stats-grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
        gap: 12px;
        margin-bottom: 16px;
    }
    .stat-cell { background: #0d1117; border-radius: 4px; padding: 10px 12px; }
    .stat-cell .s-label { font-size: 10px; color: #8b949e; text-transform: uppercase; letter-spacing: .05em; }
    .stat-cell .s-value { font-size: 16px; font-weight: 600; margin-top: 2px; }
    .signals { margin-bottom: 14px; }
    .signals h4 { font-size: 12px; color: #8b949e; text-transform: uppercase; margin-bottom: 8px; letter-spacing: .05em; }
    .signals ul { list-style: none; }
    .signals ul li::before { content: '▸ '; color: #58a6ff; }
    .signals ul li { font-family: 'Courier New', monospace; font-size: 12px; margin-bottom: 4px; }
    .beacon-row { font-size: 12px; color: #8b949e; font-family: 'Courier New', monospace; }
    footer { text-align: center; color: #30363d; font-size: 11px; margin-top: 40px; }
    """

    # ── JS ───────────────────────────────────────────────────────────────────
    js = """
    document.querySelectorAll('.card-header').forEach(function(header) {
        header.addEventListener('click', function() {
            var body = this.nextElementSibling;
            var toggle = this.querySelector('.toggle');
            if (body.style.display === 'none') {
                body.style.display = 'block';
                toggle.style.transform = 'rotate(0deg)';
            } else {
                body.style.display = 'none';
                toggle.style.transform = 'rotate(-90deg)';
            }
        });
    });
    """

    # ── summary stats ────────────────────────────────────────────────────────
    conf_colour = _CONFIDENCE_COLOURS.get(highest_confidence, "#8b949e")
    summary_html = f"""
    <div class="summary">
      <div class="stat-box">
        <div class="value">{suspicious_count}</div>
        <div class="label">Suspicious Domains</div>
      </div>
      <div class="stat-box">
        <div class="value" style="color:{conf_colour}">{html.escape(highest_confidence)}</div>
        <div class="label">Highest Confidence</div>
      </div>
    </div>
    """

    # ── domain cards ─────────────────────────────────────────────────────────
    if not results:
        cards_html = '<div class="no-results">No suspicious domains detected.</div>'
    else:
        cards = []
        for host in results:
            colour = _CONFIDENCE_COLOURS.get(host.confidence, "#8b949e")
            domain_esc = html.escape(host.domain)
            conf_esc = html.escape(host.confidence)

            signals_items = "".join(
                f"<li>{html.escape(s)}</li>" for s in host.signals
            ) or "<li>(none)</li>"

            br = host.beacon_result
            beacon_str = (
                f"Beacon: {'yes' if br.is_beacon else 'no'} | "
                f"Interval: {br.estimated_interval_seconds:.2f}s | "
                f"Regularity: {br.regularity_score:.2f}"
            )

            card = f"""
            <div class="card">
              <div class="card-header">
                <span class="card-domain">{domain_esc}</span>
                <span class="card-right">
                  <span class="badge" style="background:{colour}">{conf_esc}</span>
                  <span class="toggle">&#9660;</span>
                </span>
              </div>
              <div class="card-body">
                <div class="stats-grid">
                  <div class="stat-cell"><div class="s-label">Query Count</div><div class="s-value">{host.query_count}</div></div>
                  <div class="stat-cell"><div class="s-label">Avg Entropy</div><div class="s-value">{host.avg_entropy:.2f}</div></div>
                  <div class="stat-cell"><div class="s-label">Avg Label Len</div><div class="s-value">{host.avg_subdomain_length:.1f}</div></div>
                  <div class="stat-cell"><div class="s-label">Beacon</div><div class="s-value">{html.escape(br.confidence)}</div></div>
                  <div class="stat-cell"><div class="s-label">Unique Subdomains</div><div class="s-value">{host.unique_subdomains}</div></div>
                </div>
                <div class="signals">
                  <h4>Signals</h4>
                  <ul>{signals_items}</ul>
                </div>
                <div class="beacon-row">{html.escape(beacon_str)}</div>
              </div>
            </div>
            """
            cards.append(card)
        cards_html = "\n".join(cards)

    # ── assemble ─────────────────────────────────────────────────────────────
    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DNS Exfiltration Detection Report</title>
  <style>{css}</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>DNS Exfiltration Detection Report</h1>
    <div class="meta">{html.escape(timestamp)} &nbsp;|&nbsp; Source: {source_name}</div>
  </div>
  {summary_html}
  {cards_html}
  <footer>Generated by dns-covert-channel-research</footer>
</div>
<script>{js}</script>
</body>
</html>"""

    if output_path is not None:
        output_path.write_text(doc, encoding="utf-8")

    return doc
