# main.py

import sys
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from parsing.ast_parser import parse_c_file, parse_python_file
from agents.categorization_agent import categorize_functions
from agents.verification_agent import verify_findings
from agents.explainable_ai_agent import explain_findings
from agents.advisory_refactoring_agent import advise_findings
from dashboard.report_generator import generate_report

console = Console()

PYTHON_EXTENSIONS = {".py"}
C_EXTENSIONS      = {".c", ".cpp", ".h", ".cc"}


def print_banner(file_path: str, language: str = "C") -> None:
    console.print(Panel(
        f"[bold cyan]{language} Vulnerability Scanner[/bold cyan]\n"
        f"[dim]File:[/dim] [white]{file_path}[/white]\n"
        f"[dim]LLM:[/dim]  [white]Ollama / deepseek-coder:6.7b (local)[/white]",
        expand=False,
    ))


def print_summary(findings: list, functions_count: int) -> None:
    table = Table(title="Scan Summary", show_header=True, header_style="bold dim")
    table.add_column("Severity", style="bold", width=12)
    table.add_column("Count",    justify="right", width=8)

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


def scan_file(file_path: str) -> tuple:
    """Run the full pipeline. Returns (findings, functions_count, language)."""
    path = Path(file_path)
    if not path.exists():
        console.print(f"[red]Error: File not found: {file_path}[/red]")
        sys.exit(1)

    ext = path.suffix.lower()

    # ── Stage 1: Parse ─────────────────────────────────────
    console.rule("[bold blue]Stage 1 — Parsing")
    if ext in PYTHON_EXTENSIONS:
        language  = "Python"
        functions = parse_python_file(file_path)
    elif ext in C_EXTENSIONS:
        language  = "C"
        functions = parse_c_file(file_path)
    else:
        console.print(f"[yellow]Warning: Unknown extension '{ext}' — treating as C[/yellow]")
        language  = "C"
        functions = parse_c_file(file_path)

    console.print(f"  Language: [bold]{language}[/bold]  |  Found [bold]{len(functions)}[/bold] function(s)")

    if not functions:
        console.print("[yellow]  No functions found. Exiting.[/yellow]")
        return [], 0, language

    # ── Stage 2: Categorize ────────────────────────────────
    console.rule("[bold blue]Stage 2 — Categorization (LLM)")
    findings = categorize_functions(functions, language)
    console.print(f"  LLM flagged [bold]{len(findings)}[/bold] potential vulnerability/vulnerabilities")

    if not findings:
        console.print("[green]  No vulnerabilities detected by LLM.[/green]")
        return [], len(functions), language

    # ── Stage 3: Verify ────────────────────────────────────
    console.rule("[bold blue]Stage 3 — Verification (RAG)")
    verified = verify_findings(findings)

    if not verified:
        console.print("[green]  All findings were false positives.[/green]")
        return [], len(functions), language

    # ── Stage 4: Explain ───────────────────────────────────
    console.rule("[bold blue]Stage 4 — Explainability (LLM)")
    explained = explain_findings(verified)

    # ── Stage 5: Advise ────────────────────────────────────
    console.rule("[bold blue]Stage 5 — Advisory (LLM)")
    advised = advise_findings(explained)

    return advised, len(functions), language


if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]Usage: python main.py <path/to/file.c|file.py>[/red]")
        sys.exit(1)

    target = sys.argv[1]

    findings, functions_count, language = scan_file(target)

    print_banner(target, language)
    print_summary(findings, functions_count)

    scan_meta = {
        "file_path":         target,
        "functions_scanned": functions_count,
        "scan_timestamp":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "language":          language,
    }

    report_path = generate_report(findings, scan_meta)
    console.print(f"\n[bold green]Report saved:[/bold green] {report_path}")
    console.print("[dim]Opening in browser...[/dim]")
