"""Simple console output helpers for pyWebRecon."""
from rich.console import Console
from rich.live import Live
from rich.text import Text
from rich.console import Group
from datetime import datetime
import threading

console = Console()


class LiveStatus:
    def __init__(self, tools):
        self.status = {}
        for tool in tools:
            self.status[tool] = Text(f"⏳ {tool} pending", style="yellow")

    def update_status(self, tool_name, status_text, style="white"):
        self.status[tool_name] = Text(status_text, style=style)

    def __rich__(self):
        return Group(*self.status.values())


def run_tools_parallel(tools_dict):
    """Run multiple tools concurrently with live text output.

    Args:
        tools_dict: Dict mapping tool names to (function, args) tuples
    """
    tool_names = list(tools_dict.keys())
    live_status = LiveStatus(tool_names)
    results = {}

    with Live(live_status, refresh_per_second=4, transient=False) as live:
        def run_tool(tool_name, tool_func, tool_args):
            try:
                live_status.update_status(tool_name, f"🔄 {tool_name} running...", "blue")
                result = tool_func(*tool_args)
                timestamp = datetime.now().strftime("%H:%M:%S")
                live_status.update_status(tool_name, f"✅ {tool_name} COMPLETED {timestamp}", "green")
                results[tool_name] = (True, result)
            except Exception as e:
                timestamp = datetime.now().strftime("%H:%M:%S")
                live_status.update_status(tool_name, f"❌ {tool_name} FAILED {timestamp}", "red")
                results[tool_name] = (False, str(e))

        threads = []
        for tool_name, (tool_func, tool_args) in tools_dict.items():
            t = threading.Thread(target=run_tool, args=(tool_name, tool_func, tool_args))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

    failed = [(name, msg) for name, (success, msg) in results.items() if not success]
    if failed:
        console.print()
        console.print("[bold]Execution Summary:[/bold]")
        for tool_name, error_msg in failed:
            console.print(f"[red]✗[/red] {tool_name}: {error_msg}")
        console.print()

    return results


def info(msg: str):
    """[+] style - green bold"""
    console.print(f"[bold green][+][/bold green] {msg}")


def error(msg: str):
    """Error style - red bold"""
    console.print(f"[bold red][✗][/bold red] {msg}")
