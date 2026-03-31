# main.py

import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from parsing.ast_parser import parse_c_file
from agents.categorization_agent import categorize_functions

console = Console()


def print_banner(file_path: str) -> None:
    console.print(Panel(
        f"[bold cyan]C/C++ Vulnerability Scanner[/bold cyan]\n"
        f"[dim]File:[/dim]   [white]{file_path}[/white]\n"
        f"[dim]LLM:[/dim]    [white]Ollama / deepseek-coder:6.7b (local)[/white]\n"
        f"[dim]Parser:[/dim] [white]tree-sitter[/white]",
        expand=False,
    ))


def print_summary(findings: list, functions_count: int) -> None:
    table = Table(title="Scan Summary", show_header=True, header_style="bold dim")
    table.add_column("Severity", style="bold", width=12)
    table.add_column("Count", justify="right", width=8)

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "MEDIUM").upper()
        if sev in counts:
            counts[sev] += 1

    colors = {"CRITICAL": "red", "HIGH": "dark_orange", "MEDIUM": "yellow", "LOW": "green"}
    for sev, count in counts.items():
        table.add_row(f"[{colors[sev]}]{sev}[/{colors[sev]}]", str(count))

    table.add_section()
    table.add_row("[bold]Total[/bold]", f"[bold]{len(findings)}[/bold]")

    console.print()
    console.print(f"  Functions scanned: [bold]{functions_count}[/bold]")
    console.print(table)


def print_findings(findings: list) -> None:
    if not findings:
        return
    console.print()
    console.rule("[bold blue]Findings")
    for f in findings:
        sev = f.get("severity", "MEDIUM").upper()
        colors = {"CRITICAL": "red", "HIGH": "dark_orange", "MEDIUM": "yellow", "LOW": "green"}
        color = colors.get(sev, "white")
        cve_ids = [c.get("cve_id", "") for c in f.get("cve_matches", []) if c.get("cve_id")]
        cve_str = ", ".join(cve_ids[:3]) if cve_ids else "none"
        console.print(
            f"  [{color}]{sev}[/{color}]  [bold]{f['function_name']}[/bold]"
            f"  ({f['cwe_id']})  line {f['start_line']}"
        )
        console.print(f"    {f['description']}")
        console.print(f"    [dim]Related CVEs: {cve_str}[/dim]")
        console.print()


def scan_file(file_path: str) -> tuple:
    path = Path(file_path)
    if not path.exists():
        console.print(f"[red]Error: File not found: {file_path}[/red]")
        sys.exit(1)

    # ── Stage 1: Parse ─────────────────────────────────────
    console.rule("[bold blue]Stage 1 — Parsing (tree-sitter)")
    functions = parse_c_file(file_path)
    console.print(f"  Found [bold]{len(functions)}[/bold] function(s)")

    if not functions:
        console.print("[yellow]  No functions found. Exiting.[/yellow]")
        return [], 0

    # ── Stage 2: Categorize ────────────────────────────────
    console.rule("[bold blue]Stage 2 — Categorization (LLM + RAG)")
    findings = categorize_functions(functions, language="C")
    console.print(f"  Flagged [bold]{len(findings)}[/bold] vulnerability/vulnerabilities")

    return findings, len(functions)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]Usage: python main.py <path/to/file.c>[/red]")
        sys.exit(1)

    target = sys.argv[1]
    print_banner(target)

    findings, functions_count = scan_file(target)

    print_summary(findings, functions_count)
    print_findings(findings)
