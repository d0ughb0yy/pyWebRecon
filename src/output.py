"""Rich console output helpers for pyWebRecon."""
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich.progress import Progress, TextColumn, BarColumn
from rich.text import Text
from rich import box
from pathlib import Path
from datetime import datetime
import threading

console = Console()


class LiveStatusTable:
    """Manages a live-updating status table for concurrent tools."""
    
    def __init__(self, tools):
        """Initialize the status table with given tools."""
        self.tools = tools
        self.table = Table(box=box.ROUNDED)
        self.table.add_column("Tool", style="cyan", width=20)
        self.table.add_column("Status", style="bold", width=30)
        
        # Store Text objects for each status cell
        self.status_texts = {}
        
        # Add all rows initially with Text objects
        for tool_name in tools:
            status_text = Text("⏳ pending", style="yellow")
            self.status_texts[tool_name] = status_text
            self.table.add_row(tool_name, status_text)
    
    def update_status(self, tool_name, status_text_str, style="white"):
        """Update the status of a specific tool."""
        if tool_name in self.status_texts:
            self.status_texts[tool_name].plain = status_text_str
            self.status_texts[tool_name].style = style
    
    def get_table(self):
        """Get the current table."""
        return self.table


def run_tools_with_live_table(tools_dict):
    """Run multiple tools concurrently with a live updating status table.
    
    Args:
        tools_dict: Dict mapping tool names to (function, args) tuples
    """
    tool_names = list(tools_dict.keys())
    status_table = LiveStatusTable(tool_names)
    results = {}
    
    with Live(status_table.get_table(), refresh_per_second=4, transient=False) as live:
        def run_tool(tool_name, tool_func, tool_args):
            """Run a single tool and update its status."""
            try:
                # Mark as running
                status_table.update_status(tool_name, "🔄 running", "blue")
                
                # Run the tool
                result = tool_func(*tool_args)
                results[tool_name] = (True, result)
                
                # Mark as completed with timestamp
                timestamp = datetime.now().strftime("%H:%M:%S")
                status_table.update_status(tool_name, f"✅ COMPLETED {timestamp}", "green")
                
            except Exception as e:
                results[tool_name] = (False, str(e))
                timestamp = datetime.now().strftime("%H:%M:%S")
                status_table.update_status(tool_name, f"❌ FAILED {timestamp}", "red")
        
        # Create and start threads for all tools
        threads = []
        for tool_name, (tool_func, tool_args) in tools_dict.items():
            t = threading.Thread(target=run_tool, args=(tool_name, tool_func, tool_args))
            threads.append(t)
            t.start()
        
        # Wait for all threads to complete
        for t in threads:
            t.join()
    
    # Print errors only if any tools failed
    failed = [(name, msg) for name, (success, msg) in results.items() if not success]
    if failed:
        console.print()
        console.print("[bold]Execution Summary:[/bold]")
        console.print("-" * 50)
        for tool_name, error_msg in failed:
            console.print(f"[red]✗[/red] {tool_name}: {error_msg}")
        console.print()

    return results


def create_dot_progress():
    """Create a progress bar with dot indicators."""
    return Progress(
        TextColumn("[bold]{task.description:15}"),
        BarColumn(
            bar_width=20,
            complete_style="green",
            finished_style="green",
            pulse_style="yellow"
        ),
        TextColumn("[{task.fields[status_color]}]{task.fields[status_icon]}[/{task.fields[status_color]}]"),
        transient=False,
        console=console
    )


def info(msg: str):
    """[+] style - green bold"""
    console.print(f"[bold green][+][/bold green] {msg}")


def success(msg: str):
    """[!] style - yellow bold"""
    console.print(f"[bold yellow][!][/bold yellow] {msg}")


def warning(msg: str):
    """[*] style - blue bold"""
    console.print(f"[bold blue][*][/bold blue] {msg}")


def error(msg: str):
    """Error style - red bold"""
    console.print(f"[bold red][✗][/bold red] {msg}")


def create_status_table(tasks):
    """Create a table showing current task statuses."""
    table = Table(box=box.ROUNDED)
    table.add_column("Tool", style="cyan")
    table.add_column("Status", style="bold")
    
    status_styles = {
        "pending": ("⏳", "yellow"),
        "running": ("🔄", "blue"),
        "complete": ("✅", "green"),
        "failed": ("❌", "red")
    }
    
    for name, status in tasks.items():
        emoji, color = status_styles.get(status, ("⏳", "white"))
        table.add_row(name, f"[{color}]{emoji} {status.upper()}[/{color}]")
    
    return table
