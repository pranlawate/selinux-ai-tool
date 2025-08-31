import argparse
import requests
import json
import sys
import subprocess
import re
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.rule import Rule

# --- Configuration ---
BACKEND_URL = "http://127.0.0.1:5000/analyze-avc"

# --- Parser Logic (Integrated from parse_avc.py) ---
def parse_audit_log(log_block: str) -> dict:
    """
    Parses a multi-line audit log block containing various record types.
    """
    parsed_data = {}
    patterns = {
        "AVC": {"permission": r"denied\s+\{ ([^}]+) \}", "pid": r"pid=(\S+)", "comm": r"comm=\"([^\"]+)\"", "scontext": r"scontext=(\S+)", "tcontext": r"tcontext=(\S+)", "tclass": r"tclass=(\S+)", "dest_port": r"dest=(\S+)",},
        "CWD": {"cwd": r"cwd=\"([^\"]+)\"",},
        "PATH": {"path": r"name=\"([^\"]+)\"",},
        "SYSCALL": {"syscall": r"syscall=([\w\d]+)", "exe": r"exe=\"([^\"]+)\"",},
        "PROCTITLE": {"proctitle": r"proctitle=(\S+)",},
        "SOCKADDR": {"saddr": r"saddr=\{([^\}]+)\}",}
    }
    for line in log_block.strip().split('\n'):
        line = line.strip()
        match = re.search(r"type=(\w+)", line)
        if not match:
            continue
        log_type = match.group(1)
        if log_type in patterns:
            for key, pattern in patterns[log_type].items():
                if key not in parsed_data:
                    field_match = re.search(pattern, line)
                    if field_match:
                        value = field_match.group(1)
                        if key == 'proctitle':
                            try:
                                parsed_data[key] = bytes.fromhex(value).decode()
                            except ValueError:
                                parsed_data[key] = value.strip('"')
                        else:
                            parsed_data[key] = value.strip()
    return parsed_data

def print_summary(console: Console, parsed_log: dict):
    """Prints a formatted summary, skipping any fields that were not found."""
    if not parsed_log:
        console.print("Could not parse the provided log string.", style="bold red")
        return
    console.print(Rule("[bold green]Parsed Log Summary[/bold green]"))
    
    # Define the fields and their labels for cleaner printing
    process_fields = [
        ("Process Title", "proctitle"), ("Executable", "exe"),
        ("Process Name", "comm"), ("Process ID (PID)", "pid"),
        ("Working Dir (CWD)", "cwd"), ("Source Context", "scontext")
    ]
    action_fields = [
        ("Syscall", "syscall"), ("Permission", "permission")
    ]
    target_fields = [
        ("Target Path", "path"), ("Target Port", "dest_port"),
        ("Socket Address", "saddr"), ("Target Class", "tclass"),
        ("Target Context", "tcontext")
    ]

    # --- Process Information ---
    for label, key in process_fields:
        if parsed_log.get(key):
            console.print(f"  [bold]{label}:[/bold]".ljust(22) + f"{parsed_log[key]}")

    console.print("-" * 35)
    # --- Action Details ---
    console.print(f"  [bold]Action:[/bold]".ljust(22) + "Denied")
    for label, key in action_fields:
        if parsed_log.get(key):
            console.print(f"  [bold]{label}:[/bold]".ljust(22) + f"{parsed_log[key]}")

    console.print("-" * 35)
    # --- Target Information ---
    for label, key in target_fields:
        if parsed_log.get(key):
            console.print(f"  [bold]{label}:[/bold]".ljust(22) + f"{parsed_log[key]}")

    console.print("-" * 35)

def main_logic():
    """
    Analyzes an SELinux AVC denial log provided by the user.
    """
    # Create a Rich Console instance
    console = Console()

    console.print("📋 Please paste your SELinux AVC denial log below and press [bold yellow]Ctrl+D[/bold yellow] (or Ctrl+Z on Windows) when done:")
    avc_log = sys.stdin.read().strip()

    if not avc_log:
        console.print("Error: No log provided. Exiting.", style="bold red")
        sys.exit(1)

    # --- ADDED: Parse and display the log first ---
    parsed_log = parse_audit_log(avc_log)
    print_summary(console, parsed_log)
    # ----------------------------------------------
   
    console.print("\n🔍 Sending log to AI for analysis...")
 
    try:
        # Send the AVC log, booleans and file contexts to the server
        payload = {
                "avc_log": avc_log,
                "parsed_log": parsed_log,
                }
        response = requests.post(BACKEND_URL, json=payload)
        response.raise_for_status()

        ai_data = response.json()

        # --- Display the Results using Rich ---
        console.print(Rule("[bold cyan]AI Analysis[/bold cyan]"))
        
        # Display the explanation in a Panel
        explanation_panel = Panel(
            ai_data['explanation'],
            title="Explanation",
            border_style="green",
            expand=True
        )
        console.print(explanation_panel)

        console.print(Rule("[bold yellow]Suggested Commands[/bold yellow]"))

        # Display commands with shell syntax highlighting
        # The 'commands' value is a list, so we iterate through it
        # and create a Syntax object for each command string in the list.
        for cmd in ai_data['commands']:
            syntax = Syntax(cmd, "shell", theme="monokai", line_numbers=False)
            console.print(syntax)

        # --- ADDED: Display alternative solutions if they exist ---
        if ai_data.get("alternatives"):
            console.print(Rule("[bold magenta]Alternative Solutions[/bold magenta]"))
            for alt_cmd in ai_data["alternatives"]:
                syntax = Syntax(alt_cmd, "shell", theme="monokai", line_numbers=False)
                console.print(syntax)
        # ---------------------------------------------------------

    except requests.exceptions.RequestException as e:
        console.print(f"Error connecting to the analysis server: {e}", style="bold red")
    except (json.JSONDecodeError, KeyError):
        console.print("Error: Received an invalid or malformed response from the AI server.", style="bold red")

def main():
    """Handles command-line argument parsing and calls the main logic."""

    parser = argparse.ArgumentParser(description="An AI-powered tool for SELinux.")
    # In the future, to add arguments here,e.g:
    # parser.add_arguments("-v", "--verbose", action="store_true", help="Enable verbose output.")
    # Set the default function to be 'fix' until we need other subcommands.
    # parser.set_defaults(func=fix)

#    subparsers = parser.add_subparsers(dest='command', required=True, help='Available commands')
#    parser_fix = subparsers.add_parser('fix', help='Analyzes an SELinux AVC denial log.')
#    parser_fix.set_defaults(func=fix)

    # You could add subparsers here for future commands, but we don't need them for one command.
    # For example:
    # subparsers = parser.add_subparsers(dest='command')
    # parser_other = subparsers.add_parser('other_command', help='Does something else.')
    # parser_other.set_defaults(func=other_function)

    args = parser.parse_args()
    main_logic()

if __name__ == "__main__":
    main()
