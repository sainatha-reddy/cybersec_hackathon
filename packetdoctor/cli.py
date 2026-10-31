"""Command-line interface.

    packetdoctor analyze capture.pcap [--json out.json] [--html out.html] [--anonymize]
    packetdoctor serve [--port 8000]
    packetdoctor samples
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .config import Limits, Settings
from .ingest import CaptureError

# Legacy Windows consoles (cp1252) cannot print every character; replace
# instead of crashing.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(errors="replace")
    except (AttributeError, ValueError):
        pass

app = typer.Typer(add_completion=False, help="PacketDoctor: find faults and attacks in packet captures, explained in plain language.")
console = Console()

VERDICT_STYLE = {"ATTACK": "bold white on red", "FAULT": "bold black on yellow", "UNCERTAIN": "bold white on blue"}
GRADE_STYLE = {"Healthy": "green", "Minor issues": "yellow", "Degraded": "dark_orange", "Critical": "red"}
SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


def _settings(max_mb: int) -> Settings:
    return Settings(limits=Limits(max_file_bytes=max_mb * 1024 * 1024))


@app.command()
def analyze(
    capture: Path = typer.Argument(..., help="pcap or pcapng file to analyse"),
    json_out: Optional[Path] = typer.Option(None, "--json", help="also write the full report as JSON"),
    html_out: Optional[Path] = typer.Option(None, "--html", help="also write a self-contained HTML report"),
    anonymize: bool = typer.Option(False, "--anonymize", help="replace IP and MAC addresses with pseudonyms in all output"),
    evidence: int = typer.Option(5, "--evidence", "-e", help="evidence packets to print per incident (0 = none)"),
    max_mb: int = typer.Option(500, "--max-mb", help="refuse captures larger than this many MB"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="only print the summary table"),
):
    """Analyse a capture and print the diagnosis."""
    from .engine import analyze as run_analysis

    try:
        with console.status("Analysing capture...", spinner="line"):
            report = run_analysis(capture, _settings(max_mb), anonymize=anonymize)
    except CaptureError as exc:
        console.print(f"[bold red]Cannot analyse:[/] {escape(str(exc))}")
        raise typer.Exit(2)
    print_report(report, evidence=0 if quiet else evidence, detailed=not quiet)
    if json_out:
        _write_private(json_out, json.dumps(report, indent=2, default=str))
        console.print(f"JSON report written to [bold]{escape(str(json_out))}[/]")
    if html_out:
        from .report.html import render_html

        _write_private(html_out, render_html(report))
        console.print(f"HTML report written to [bold]{escape(str(html_out))}[/]")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="interface to bind (default: this computer only)"),
    port: int = typer.Option(8000, help="port for the web dashboard"),
):
    """Start the local web dashboard."""
    import uvicorn

    if host not in ("127.0.0.1", "localhost", "::1"):
        console.print("[yellow]Warning:[/] the dashboard will be reachable from other machines. Uploaded captures may contain sensitive data.")
    console.print(f"PacketDoctor dashboard on [bold]http://{host}:{port}[/]  (Ctrl+C to stop)")
    uvicorn.run("packetdoctor.web.app:app", host=host, port=port, log_level="warning")


@app.command()
def samples():
    """List the bundled sample captures."""
    table = Table(title="Sample captures", show_lines=False)
    table.add_column("File")
    table.add_column("Size", justify="right")
    for f in sorted(SAMPLES_DIR.glob("*.pcap*")):
        table.add_row(str(f.relative_to(SAMPLES_DIR.parent)), f"{f.stat().st_size // 1024} KB")
    console.print(table)
    console.print("Try: [bold]packetdoctor analyze samples/mixed_fault_and_attack.pcap[/]")


@app.command()
def version():
    """Print the version."""
    console.print(f"PacketDoctor {__version__}")


def _write_private(path: Path, text: str) -> None:
    """Reports can contain network details: create them readable by the owner only where supported."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


# --- rendering ---------------------------------------------------------------


def print_report(report: dict, evidence: int = 5, detailed: bool = True) -> None:
    cap, health, summ = report["capture"], report["health"], report["summary"]
    head = Text()
    head.append(f"{cap['file_name']}", style="bold")
    head.append(f"  {cap['packets']:,} packets, {cap['duration_s']:.1f} s, {cap['format']}\n")
    head.append("Network health: ")
    head.append(f"{health['score']}/100 {health['grade']}", style=f"bold {GRADE_STYLE.get(health['grade'], 'white')}")
    head.append(f"   {summ['attacks']} attack(s), {summ['faults']} fault(s), {summ['uncertain']} uncertain\n")
    head.append(health["summary"], style="italic")
    gw = report["network"].get("gateway_ip")
    if gw:
        head.append(f"\nGateway: {gw} ({report['network'].get('gateway_mac')})", style="dim")
    console.print(Panel(head, title=f"PacketDoctor {report['tool']['version']}", border_style="cyan"))
    for w in cap["warnings"]:
        console.print(f"[yellow]! {escape(w)}[/]")
    for e in report.get("detector_errors", []):
        console.print(f"[red]! detector error: {escape(e)}[/]")

    if not report["incidents"]:
        console.print("[green]No problems found.[/]")
        return

    table = Table(show_header=True, header_style="bold", expand=True)
    table.add_column("ID", no_wrap=True)
    table.add_column("Verdict", no_wrap=True)
    table.add_column("Sev", justify="center")
    table.add_column("When (s)", no_wrap=True)
    table.add_column("Problem")
    for inc in report["incidents"]:
        table.add_row(
            inc["id"],
            Text(f" {inc['verdict']} ", style=VERDICT_STYLE[inc["verdict"]]),
            "!" * inc["severity"],
            f"{inc['rel_start']:.1f}-{inc['rel_end']:.1f}",
            Text(f"{inc['label']}: ", style="bold") + Text(inc["title"]),
        )
    console.print(table)
    if not detailed:
        return
    for inc in report["incidents"]:
        console.print(_incident_panel(inc, report["evidence"], evidence))


def _incident_panel(inc: dict, ev_map: dict, n_evidence: int) -> Panel:
    ex = inc["explanation"]
    t = Text()
    t.append("What happened\n", style="bold underline")
    t.append(ex["what"] + "\n\n")
    if ex["why"]:
        t.append("Why it matters: ", style="bold")
        t.append(ex["why"] + "\n\n")
    verdict_word = {"ATTACK": "an attack", "FAULT": "a fault, not an attack", "UNCERTAIN": "uncertain"}[inc["verdict"]]
    t.append(f"Why we think this is {verdict_word} ", style="bold")
    t.append(f"(confidence {inc['confidence']:.0%})\n", style="dim")
    for e in inc["evidence_for_attack"][:6]:
        t.append("  + ", style="red bold")
        t.append(e["text"] + "\n")
    for e in inc["evidence_for_fault"][:4]:
        t.append("  - ", style="green bold")
        t.append(e["text"] + "\n")
    for note in inc["notes"]:
        t.append("  > ", style="cyan bold")
        t.append(note + "\n")
    if inc["related"]:
        t.append("\nAlso seen as: ", style="bold")
        t.append("; ".join(r["title"] for r in inc["related"]) + "\n")
    if inc["consequences"]:
        t.append("\nKnock-on effects\n", style="bold")
        for c in inc["consequences"]:
            t.append("  -> ", style="magenta bold")
            t.append(f"{c['title']}", style="bold")
            t.append(f" ({c['reason']})\n")
    t.append("\nLikely cause: ", style="bold")
    t.append(ex["cause"] + "\n")
    t.append("What to do\n", style="bold")
    for i, fix in enumerate(ex["fixes"], 1):
        t.append(f"  {i}. {fix}\n")
    if n_evidence and inc["packet_ids"]:
        t.append(f"\nEvidence packets ({len(inc['packet_ids'])} cited; numbers match Wireshark's No. column)\n", style="bold")
        for pid in inc["packet_ids"][:n_evidence]:
            row = ev_map.get(str(pid))
            if row:
                t.append(f"  #{row['no']:<6} {row['time']:>9.3f}s  {row['src']} -> {row['dst']}  {row['info']}\n", style="dim")
    if ex.get("technical"):
        t.append("\nTechnical: ", style="dim bold")
        t.append(ex["technical"], style="dim")
    style = {"ATTACK": "red", "FAULT": "yellow", "UNCERTAIN": "blue"}[inc["verdict"]]
    return Panel(t, title=f"{inc['id']}  {inc['verdict']}  {inc['label']}", title_align="left", border_style=style)


def main():
    app()


if __name__ == "__main__":
    main()
