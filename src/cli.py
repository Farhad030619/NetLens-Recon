"""
NetLens-Recon CLI
Command-line interface with Rich formatting for automated visual reconnaissance.
Author: Farhad Jelve (CCNP Enterprise, CCNA, B.Sc. EE KTH)
"""

import asyncio
import os
import sys
import time
from typing import List

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src import __version__
from src.scanner import parse_targets, ReconScanner
from src.analyzer import ReconAnalyzer
from src.reporter import ReconReporter

console = Console()

BANNER = r"""
 [bold cyan] _   _      _   _                         ____                      [/bold cyan]
 [bold cyan]| \ | | ___| |_| |    ___ _ __  ___       |  _ \ ___  ___ ___  _ __  [/bold cyan]
 [bold cyan]|  \| |/ _ \ __| |   / _ \ '_ \/ __| _____| |_) / _ \/ __/ _ \| '_ \ [/bold cyan]
 [bold cyan]| |\  |  __/ |_| |__|  __/ | | \__ \_____|  _ <  __/ (_| (_) | | | |[/bold cyan]
 [bold cyan]|_| \_|\___|\__|_____\___|_| |_|___/      |_| \_\___|\___\___/|_| |_|[/bold cyan]
"""


def print_banner():
    """Print stylish terminal header with author metadata."""
    console.print(BANNER)
    info_text = Text()
    info_text.append(" 🛡️  Next-Gen Attack Surface & Visual Recon Engine ", style="bold white on cyan")
    info_text.append(f"  v{__version__}\n", style="bold cyan")
    info_text.append(" 👤 Author: ", style="bold slate_grey")
    info_text.append("Farhad Jelve ", style="bold white")
    info_text.append("(CCNP Enterprise, CCNA, B.Sc. Electrical Engineering KTH)\n", style="italic cyan")
    info_text.append(" 🌐 GitHub: https://github.com/Farhad030619/NetLens-Recon", style="dim underline")

    console.print(Panel(info_text, border_style="cyan", padding=(0, 1)))
    console.print()


@click.group()
@click.version_option(__version__, prog_name="NetLens-Recon")
def main():
    """NetLens-Recon: Automated Attack Surface & Visual Reconnaissance Engine."""
    pass


@main.command()
@click.argument("targets", nargs=-1)
@click.option("-f", "--file", "target_file", type=click.Path(exists=True), help="File containing target domains, URLs, or CIDR blocks.")
@click.option("-p", "--ports", default="80,443", help="Comma-separated list of ports to probe (e.g. 80,443,8080,8443).")
@click.option("-c", "--concurrency", default=8, type=int, help="Number of concurrent browser instances (default: 8).")
@click.option("--timeout", default=15.0, type=float, help="Page navigation timeout in seconds (default: 15.0).")
@click.option("-o", "--output", "output_dir", default="./output", help="Output directory for reports and screenshots (default: ./output).")
@click.option("--no-preflight", is_flag=True, default=False, help="Skip TCP pre-flight check and attempt direct browser capture on all targets.")
@click.option("--cluster-threshold", default=4, type=int, help="Perceptual hash Hamming distance for visual deduplication (default: 4).")
@click.option("--headless/--no-headless", default=True, help="Run browser in headless mode (default: headless).")
def scan(
    targets,
    target_file,
    ports,
    concurrency,
    timeout,
    output_dir,
    no_preflight,
    cluster_threshold,
    headless
):
    """
    Launch visual reconnaissance against targets.
    
    Examples:
      python3 -m src.cli scan https://example.com
      python3 -m src.cli scan 192.168.1.0/28 -p 80,443,8080
      python3 -m src.cli scan -f targets.txt -c 10 -o ./reports
    """
    print_banner()

    target_list: List[str] = list(targets)

    # Read targets from file if specified
    if target_file:
        try:
            with open(target_file, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                target_list.extend(lines)
        except Exception as e:
            console.print(f"[bold red]❌ Error reading target file:[/bold red] {e}")
            sys.exit(1)

    if not target_list:
        console.print("[bold red]❌ No targets provided.[/bold red] Specify target arguments or use [cyan]-f/--file targets.txt[/cyan].")
        sys.exit(1)

    # Parse ports
    try:
        port_list = [int(p.strip()) for p in ports.split(",") if p.strip()]
    except ValueError:
        console.print("[bold red]❌ Invalid port format.[/bold red] Use comma-separated numbers (e.g. 80,443,8080).")
        sys.exit(1)

    # Parse and expand targets
    parsed_targets = parse_targets(target_list, default_ports=port_list)
    console.print(f"[bold green]✓[/bold green] Ingested [bold]{len(target_list)}[/bold] input items ➔ expanded into [bold cyan]{len(parsed_targets)}[/bold cyan] endpoint candidates.")

    start_time = time.perf_counter()

    # 1. Scanner Execution
    scanner = ReconScanner(
        concurrency=concurrency,
        page_timeout_sec=timeout,
        output_dir=output_dir,
        headless=headless
    )

    with console.status("[bold cyan]Running reconnaissance pipeline...", spinner="dots"):
        results = asyncio.run(scanner.run(parsed_targets, skip_preflight=no_preflight))

    if not results:
        console.print("[bold yellow]⚠️ No active web services responded to probe.[/bold yellow]")
        return

    # 2. Intelligence Analysis (Tech Stack, HVT heuristics, Visual Clustering)
    console.print(f"[cyan]🧠 Analyzing {len(results)} responses (tech stack, HVT heuristics, dHash visual clustering)...[/cyan]")
    analyzer = ReconAnalyzer(
        cluster_threshold=cluster_threshold,
        base_dir=output_dir
    )
    clusters = analyzer.process(results)

    # 3. Report Generation
    console.print("[cyan]📊 Generating standalone HTML5/Tailwind dashboard and JSON export...[/cyan]")
    reporter = ReconReporter(
        template_dir="./templates",
        output_dir=output_dir
    )

    total_duration = time.perf_counter() - start_time
    report_path = reporter.export(
        results=results,
        clusters=clusters,
        total_targets_supplied=len(parsed_targets),
        duration_seconds=total_duration
    )

    # 4. Display Rich Terminal Results Table
    console.print()
    table = Table(
        title="🛡️ NetLens-Recon Discovered Endpoints",
        border_style="cyan",
        header_style="bold cyan",
        show_lines=True
    )
    table.add_column("Status", justify="center", style="bold")
    table.add_column("URL", style="cyan")
    table.add_column("Title", style="white")
    table.add_column("Tech Stack", style="magenta")
    table.add_column("HVT Flags", style="bold red")
    table.add_column("Cluster", justify="center", style="purple")

    for r in results:
        status_styled = f"[green]{r.status_code}[/green]" if r.status_code == 200 else f"[yellow]{r.status_code or 'ERR'}[/yellow]"
        tech_styled = ", ".join(r.technologies[:3]) if r.technologies else "[dim]Unknown[/dim]"
        hvt_styled = " ".join([f"🚨{f}" for f in r.hvt_flags]) if r.hvt_flags else "[dim]-[/dim]"
        title_disp = (r.page_title[:32] + "...") if r.page_title and len(r.page_title) > 35 else (r.page_title or "[dim]Untitled[/dim]")
        cluster_disp = f"#C{r.cluster_id}" if r.cluster_id else "-"

        table.add_row(
            status_styled,
            r.url,
            title_disp,
            tech_styled,
            hvt_styled,
            cluster_disp
        )

    console.print(table)
    console.print()

    # Success Summary Panel
    hvt_total = sum(1 for r in results if r.is_hvt)
    summary_panel = Text()
    summary_panel.append(f"✓ Recon job finished in {total_duration:.2f} seconds\n", style="bold green")
    summary_panel.append(f"• Total Endpoints Scanned: {len(results)}\n", style="white")
    summary_panel.append(f"• High-Value Targets (HVT): {hvt_total}\n", style="bold red" if hvt_total > 0 else "white")
    summary_panel.append(f"• Unique Visual Clusters: {len(clusters)}\n", style="purple")
    summary_panel.append(f"\n📂 Interactive Report Dashboard:\n", style="bold cyan")
    summary_panel.append(f"  file://{report_path}\n", style="bold underline cyan")
    summary_panel.append(f"📂 Structured JSON Results:\n", style="bold slate_grey")
    summary_panel.append(f"  {os.path.join(output_dir, 'results.json')}", style="slate_grey")

    console.print(Panel(summary_panel, title="[bold green]Scan Completed Successfully[/bold green]", border_style="green"))


if __name__ == "__main__":
    main()
