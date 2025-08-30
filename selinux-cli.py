import argparse
import requests
import json
import sys
import subprocess
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.rule import Rule
from parse_avc import parse_audit_log, print_summary # Import the Audit parser functions

# --- Configuration ---
BACKEND_URL = "http://127.0.0.1:5000/analyze-avc"

def fix(args):
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
    console.print(Rule("[bold green]Parsed Log Summary[/bold green]"))
    parsed_log = parse_audit_log(avc_log)
    print_summary(parsed_log)
    # ----------------------------------------------
   
    # Collect the full, live SELinux context from the system
    selinux_context = collect_selinux_context(console)

    console.print("\n🔍 Sending log to AI for analysis...")
 
    try:
        # Send the AVC log, booleans and file contexts to the server
        payload = {
                "avc_log": avc_log,
                "selinux_context": selinux_context
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

def collect_selinux_context(console: Console) -> str:
    """Collects a comprehensive snapshot of the live SELinux policy."""
    console.print("\n🔍 Collecting live SELinux policy snapshot...")

    # List of commands to run to get a full system context
    commands = {
        "Booleans": ["getsebool", "-a"],
        "File Contexts": ["semanage", "fcontext", "-l"],
        "Classes": ["seinfo", "--class"],
        "Roles": ["seinfo", "--role"],
        "Types": ["seinfo", "--type"],
        "Users": ["seinfo", "--user"]
    }

    full_context = ""
    for name, command in commands.items():
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            # Add a header for each section for the AI's context
            full_context += f"--- {name} ---\n{result.stdout.strip()}\n\n"
        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            error_msg = e.stderr.strip() if hasattr(e, 'stderr') and e.stderr else str(e)
            console.print(f"Warning: Could not collect {name.lower()}: {error_msg}", style="yellow")

    return full_context

def main():

    parser = argparse.ArgumentParser(description="An AI-powered tool for SELinux.")
    # Set the default function to be 'fix' until we need other subcommands.
    parser.set_defaults(func=fix)

#    subparsers = parser.add_subparsers(dest='command', required=True, help='Available commands')
#    parser_fix = subparsers.add_parser('fix', help='Analyzes an SELinux AVC denial log.')
#    parser_fix.set_defaults(func=fix)

    # You could add subparsers here for future commands, but we don't need them for one command.
    # For example:
    # subparsers = parser.add_subparsers(dest='command')
    # parser_other = subparsers.add_parser('other_command', help='Does something else.')
    # parser_other.set_defaults(func=other_function)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
