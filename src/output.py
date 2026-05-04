"""Simple console output helpers for pyWebRecon."""
from rich.console import Console
from rich.live import Live
from rich.text import Text
from rich.console import Group
from datetime import datetime
import concurrent.futures

console = Console()


class LiveStatus:
    def __init__(self, tools):
        self.status = {}
        for tool in tools:
            self.status[tool] = Text(f"- {tool} pending", style="yellow")

    def updateStatus(self, tool_name, status_text, style="white"):
        self.status[tool_name] = Text(status_text, style=style)

    def __rich__(self):
        return Group(*self.status.values())


def runToolsParallel(tools_dict):
    """Run multiple tools concurrently with live text output.

    Args:
        tools_dict: Dict mapping tool names to (function, args) tuples
    
    Returns:
        Dict mapping tool names to their return values (sets of subdomains)
    """
    tool_names = list(tools_dict.keys())
    live_status = LiveStatus(tool_names)
    results = {}
    errors = {}

    with Live(live_status, refresh_per_second=4, transient=False) as live:
        def runTool(tool_name, tool_func, tool_args):
            try:
                live_status.updateStatus(tool_name, f"+ {tool_name} running...", "cyan")
                result = tool_func(*tool_args)
                timestamp = datetime.now().strftime("%H:%M:%S")
                live_status.updateStatus(tool_name, f"+ {tool_name} COMPLETED {timestamp}", "green")
                results[tool_name] = result
            except Exception as e:
                timestamp = datetime.now().strftime("%H:%M:%S")
                live_status.updateStatus(tool_name, f"! {tool_name} FAILED {timestamp}", "red")
                errors[tool_name] = str(e)

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(tools_dict)) as executor:
            futures = {
                executor.submit(runTool, tool_name, tool_func, tool_args): tool_name
                for tool_name, (tool_func, tool_args) in tools_dict.items()
            }
            concurrent.futures.wait(futures)
    
    if errors:
        console.print()
        console.print("[bold]Execution Summary:[/bold]")
        for tool_name, error_msg in errors.items():
            console.print(f"[red]![/red] {tool_name}: {error_msg}")
        console.print()
    
    return results


def info(msg: str):
    """[+] style - green bold"""
    console.print(f"[bold green][+][/bold green] {msg}")


def error(msg: str):
    """Error style - red bold"""
    console.print(f"[bold red][!][/bold red] {msg}")
