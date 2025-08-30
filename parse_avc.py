import argparse
import re
import sys

def parse_audit_log(log_block: str) -> dict:
    """
    Parses a raw AVC denial log string and extracts key fields.
    """
    parsed_data = {}
    patterns = {
        "AVC": {
            "permission": r"denied\s+\{ ([^}]+) \}",
            "pid": r"pid=(\S+)",
            "comm": r"comm=\"([^\"]+)\"",
            "path": r"path=\"([^\"]+)\"",
            "scontext": r"scontext=(\S+)",
            "tcontext": r"tcontext=(\S+)",
            "tclass": r"tclass=(\S+)",
            "dest_port": r"dest=(\S+)",
        }
        ,
        "CWD": {
            "cwd": r"cwd=\"([^\"]+)\"",
        },
        "PATH": {
            # Capture the first path found, which is usually the most relevant
            "path": r"name=\"([^\"]+)\"",
        },
        "SYSCALL": {
            "syscall": r"syscall=([\w\d]+)",
            "exe": r"exe=\"([^\"]+)\"",
        },
        "PROCTITLE": {
            # Decode proctitle from hex if needed, otherwise grab the string
            "proctitle": r"proctitle=(\S+)",
        },
        "SOCKADDR": {
            "saddr": r"saddr=\{([^\}]+)\}",
        }
    }

    # Split the log block into individual lines
    for line in log_block.strip().split('\n'):
        line = line.strip()
        match = re.search(r"type=(\w+)", line)
        if not match:
            continue
        
        log_type = match.group(1)
        
        # Apply the patterns for the detected log type
        if log_type in patterns:
            for key, pattern in patterns[log_type].items():
                # Avoid overwriting already found data (e.g., path from AVC)
                if key not in parsed_data:
                    field_match = re.search(pattern, line)
                    if field_match:
                        parsed_data[key] = field_match.group(1).strip()

    return parsed_data

def print_summary(parsed_log: dict):
    """Prints a formatted summary of the parsed log data."""
    if not parsed_log:
        print("Could not parse the provided log string. Please ensure it's a valid AVC denial.")
        return

    print("\n--- SELinux Audit Log Summary ---")
    
    
    # --- Process Information ---
    print(f"  Process Title:    {parsed_log.get('proctitle','N/A')}")
    print(f"  Executable:       {parsed_log.get('exe', 'N/A')}")
    print(f"  Process Name:     {parsed_log.get('comm', 'N/A')}")
    print(f"  Process ID (PID):   {parsed_log.get('pid', 'N/A')}")
    print(f"  Working Dir (CWD):  {parsed_log.get('cwd', 'N/A')}")
    print(f"  Source Context:     {parsed_log.get('scontext', 'N/A')}")
    
    print("-" * 35)
    # --- Action Details ---
    print(f"  Action:             Denied")
    print(f"  Syscall:            {parsed_log.get('syscall', 'N/A')}")
    print(f"  Permission:         {parsed_log.get('permission', 'N/A')}")
    print("-" * 35)
    
    # --- Target Information ---
    if parsed_log.get('path'):
        print(f"  Target Path:        {parsed_log.get('path', 'N/A')}")
    elif parsed_log.get('dest_port'):
        print(f"  Target Port:        {parsed_log.get('dest_port', 'N/A')}")
        print(f"  Socket Address:     {parsed_log.get('saddr','N/A')}")

    print(f"  Target Class:       {parsed_log.get('tclass', 'N/A')}")
    print(f"  Target Context:     {parsed_log.get('tcontext', 'N/A')}")
    print("-" * 35)

def main():
    """
    Main function to handle command-line arguments and print the parsed output.
    """
    parser = argparse.ArgumentParser(
        description="A tool to parse an SELinux AVC denial log from a file or user prompt."
    )
    parser.add_argument(
        "-f", "--file", 
        type=str, 
        help="Path to a file containing the raw AVC log string."
    )
    
    args = parser.parse_args()
    
    log_string = ""
    if args.file:
        try:
            with open(args.file, 'r') as f:
                log_string = f.read()
        except FileNotFoundError:
            print(f"Error: File not found at '{args.file}'")
            sys.exit(1)
    else:
        print("📋 Please paste your SELinux AVC denial log below and press Ctrl+D when done:")
        log_string = sys.stdin.read()

    parsed_log = parse_audit_log(log_string)
    print_summary(parsed_log)


if __name__ == "__main__":
    main()
