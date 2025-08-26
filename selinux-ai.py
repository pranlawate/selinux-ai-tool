import argparse
import requests
import json
import sys
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.rule import Rule

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

    console.print("\n🔍 Sending log to AI for analysis...")

    try:
        response = requests.post(BACKEND_URL, json={"log": avc_log})
        response.raise_for_status()

        ai_response_str = response.json()
        ai_data = json.loads(ai_response_str)

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
        for cmd in ai_data['commands']:
            syntax = Syntax(cmd, "shell", theme="monokai", line_numbers=False)
            console.print(syntax)

    except requests.exceptions.RequestException as e:
        console.print(f"Error connecting to the analysis server: {e}", style="bold red")
    except (json.JSONDecodeError, KeyError):
        console.print("Error: Received an invalid or malformed response from the AI server.", style="bold red")

def main():
    parser = argparse.ArgumentParser(description="An AI-powered tool for SELinux.")
    subparsers = parser.add_subparsers(dest='command', required=True, help='Available commands')

    parser_fix = subparsers.add_parser('fix', help='Analyzes an SELinux AVC denial log.')
    parser_fix.set_defaults(func=fix)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
