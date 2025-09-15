#!/usr/bin/env python3
"""
Enhanced SELinux CLI with MCP Server Integration
Combines your existing parsing logic with MCP-based advanced analysis
"""

import asyncio
import json
import sys
import subprocess
import re
import os
from typing import Dict, List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

# MCP Client imports
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

class SELinuxMCPClient:
    def __init__(self):
        self.console = Console()
        self.session: Optional[ClientSession] = None
        self.session_cm = None
        self.mcp_enabled = False  # Disable MCP by default to avoid runtime issues

    async def start_mcp_session(self):
        """Start MCP session with SELinux server"""
        try:
            import os
            server_params = StdioServerParameters(
                command="python3",
                args=[os.path.join(os.path.dirname(__file__), "selinux_mcp_server.py")],
                env=None
            )

            # Use timeout for connection attempt
            try:
                self.session_cm = stdio_client(server_params)
                read_stream, write_stream = await asyncio.wait_for(
                    self.session_cm.__aenter__(), timeout=5.0
                )

                from mcp.client.session import ClientSession
                self.session = ClientSession(read_stream, write_stream)
                await asyncio.wait_for(self.session.initialize(), timeout=5.0)

                self.console.print("✅ MCP Server connected successfully", style="green")
                return True
            except asyncio.TimeoutError:
                # Disable MCP if connection times out
                self.mcp_enabled = False
                self.session = None
                self.session_cm = None
                return False

        except Exception as e:
            # Disable MCP on any error
            self.mcp_enabled = False
            self.session = None
            self.session_cm = None
            return False

    async def analyze_with_mcp(self, avc_log: str, parsed_log: dict, system_context: str = "") -> dict:
        """Analyze AVC denial using MCP server"""
        if not self.session or not self.mcp_enabled:
            return await self.fallback_analysis(avc_log, parsed_log)

        try:
            result = await self.session.call_tool(
                "analyze_avc_denial",
                {
                    "avc_log": avc_log,
                    "parsed_log": parsed_log,
                    "system_context": system_context
                }
            )

            # Parse MCP response
            if result.content and len(result.content) > 0:
                response_text = result.content[0].text
                return json.loads(response_text)
            else:
                return await self.fallback_analysis(avc_log, parsed_log)

        except Exception as e:
            self.console.print(f"🔄 MCP analysis failed, using fallback: {e}", style="yellow")
            return await self.fallback_analysis(avc_log, parsed_log)

    async def search_policy(self, source_type: str = "", target_type: str = "",
                          object_class: str = "", permission: str = "") -> str:
        """Search SELinux policy using MCP"""
        if not self.session or not self.mcp_enabled:
            return "MCP not available for policy search"

        try:
            result = await self.session.call_tool(
                "search_selinux_policy",
                {
                    "source_type": source_type,
                    "target_type": target_type,
                    "object_class": object_class,
                    "permission": permission
                }
            )

            return result.content[0].text if result.content else "No results"

        except Exception as e:
            return f"Error searching policy: {e}"

    async def get_relevant_booleans(self, service: str = "", pattern: str = "") -> str:
        """Get relevant SELinux booleans using MCP"""
        if not self.session or not self.mcp_enabled:
            return "MCP not available for boolean search"

        try:
            result = await self.session.call_tool(
                "get_selinux_booleans",
                {
                    "service": service,
                    "pattern": pattern
                }
            )

            return result.content[0].text if result.content else "No booleans found"

        except Exception as e:
            return f"Error getting booleans: {e}"

    async def audit2allow_check(self, avc_log: str) -> str:
        """Get audit2allow recommendations using MCP"""
        if not self.session or not self.mcp_enabled:
            return "MCP not available for audit2allow"

        try:
            result = await self.session.call_tool(
                "audit2allow_analysis",
                {"avc_log": avc_log}
            )

            return result.content[0].text if result.content else "No recommendations"

        except Exception as e:
            return f"Error running audit2allow: {e}"

    async def search_knowledge_base(self, query: str) -> str:
        """Search RAG knowledge base using MCP"""
        if not self.session or not self.mcp_enabled:
            return "MCP not available for knowledge search"

        try:
            result = await self.session.call_tool(
                "rag_knowledge_search",
                {"query": query}
            )

            return result.content[0].text if result.content else "No knowledge found"

        except Exception as e:
            return f"Error searching knowledge base: {e}"

    async def fallback_analysis(self, avc_log: str, parsed_log: dict) -> dict:
        """Fallback analysis using improved SELinux logic"""
        scontext = parsed_log.get("scontext", "")
        tcontext = parsed_log.get("tcontext", "")
        tclass = parsed_log.get("tclass", "")
        permission = parsed_log.get("permission", "")
        path = parsed_log.get("path", "")
        comm = parsed_log.get("comm", "")

        # Improved SELinux analysis logic
        if "socket" in tclass or "tcp_socket" in tclass:
            problem_type = "BOOLEAN"
            source_type = scontext.split(':')[2] if scontext and len(scontext.split(':')) > 2 else "unknown"
            solution = f"{source_type}_can_network_connect"
            explanation = f"Network connection denied. Need to enable boolean: {solution}"
            commands = [f"setsebool -P {solution} on"]
        else:
            problem_type = "FILE_CONTEXT"
            # Better context analysis
            source_type = scontext.split(':')[2] if scontext and len(scontext.split(':')) > 2 else "unknown"
            target_type = tcontext.split(':')[2] if tcontext and len(tcontext.split(':')) > 2 else "unknown"

            # Determine correct context based on path and process
            if "/var/www" in path and "httpd" in comm:
                if path.endswith(('.php', '.cgi', '.pl', '.py')):
                    solution = "httpd_exec_t"
                else:
                    solution = "httpd_t"  # For regular web content
            elif "/etc" in path:
                solution = "etc_t"
            elif "/var/log" in path:
                solution = "var_log_t"
            elif "/home" in path:
                solution = "user_home_t"
            elif "httpd" in comm:
                solution = "httpd_t"  # Default for httpd content
            else:
                # Fallback to appropriate type
                solution = f"{source_type}_t" if source_type != "unknown" else "admin_home_t"

            explanation = f"File context mismatch. {path} should have context: {solution}"

            if path and path != "/unknown/path":
                commands = [
                    f"semanage fcontext -a -t {solution} '{path}'",
                    f"restorecon -v '{path}'"
                ]
            else:
                commands = [
                    f"# Unable to determine file path from log",
                    f"# Use: semanage fcontext -a -t {solution} '/path/to/file'",
                    f"# Then: restorecon -v '/path/to/file'"
                ]

        return {
            "cause": f"SELinux {problem_type.lower().replace('_', ' ')}",
            "solution": solution,
            "commands": commands,
            "explanation": explanation,
            "confidence": "medium",
            "method": "enhanced_heuristic"
        }

    def parse_audit_log(self, log_block: str) -> dict:
        """Enhanced audit log parser based on parse_avc.py logic"""
        from datetime import datetime

        parsed_data = {}

        # Extract timestamp with multiple format support
        timestamp_pattern = re.search(r'msg=audit\(([^)]+)\)', log_block)
        if timestamp_pattern:
            timestamp_str = timestamp_pattern.group(1).rsplit(':',1)[0]
            try:
                # Try unix timestamp first
                dt_object = datetime.fromtimestamp(float(timestamp_str))
                parsed_data['datetime_str'] = dt_object.strftime('%Y-%m-%d %H:%M:%S')
                parsed_data['timestamp'] = dt_object.timestamp()
            except ValueError:
                try:
                    # Try human-readable format
                    dt_object = datetime.strptime(timestamp_str, '%m/%d/%Y %H:%M:%S.%f')
                    parsed_data['datetime_str'] = dt_object.strftime('%Y-%m-%d %H:%M:%S')
                except ValueError:
                    pass

        # Enhanced patterns with better field extraction
        patterns = {
            "AVC": {
                "permission": r"denied\s+\{ ([^}]+) \}",
                "pid": r"pid=(\S+)",
                "comm": r"comm=(?:\"([^\"]+)\"|([^\s]+))",  # Handle quoted/unquoted
                "path": r"path=\"([^\"]+)\"",
                "path_unquoted": r"path=([^\s]+)",
                "dev": r"dev=\"?([^\"\\s]+)\"?",
                "ino": r"ino=(\d+)",
                "scontext": r"scontext=(\S+)",
                "tcontext": r"tcontext=(\S+)",
                "tclass": r"tclass=(\S+)",
                "dest_port": r"dest=(\S+)",
                "permissive": r"permissive=(\d+)"
            },
            "CWD": {"cwd": r"cwd=\"([^\"]+)\""},
            "PATH": {
                "path": r"name=\"([^\"]+)\"",
                "path_unquoted": r"name=([^\s]+)",
                "inode": r"inode=(\d+)",
                "dev": r"dev=([^\s]+)"
            },
            "SYSCALL": {
                "syscall": r"syscall=([\w\d]+)",
                "exe": r"exe=\"([^\"]+)\""
            },
            "PROCTITLE": {"proctitle": r"proctitle=(.+)"},
            "SOCKADDR": {"saddr": r"saddr=\{([^\}]+)\}"}
        }

        # Extract shared context from non-AVC lines first
        shared_context = {}
        for line in log_block.strip().split('\n'):
            line = line.strip()
            match = re.search(r"type=(\w+)", line)
            if not match:
                continue
            log_type = match.group(1)

            if log_type in patterns and log_type != "AVC":
                for key, pattern in patterns[log_type].items():
                    field_match = re.search(pattern, line)
                    if field_match:
                        value = field_match.group(1)
                        if key == 'proctitle':
                            # Handle hex-encoded proctitle
                            value = value.strip()
                            if value.startswith('"') and value.endswith('"'):
                                shared_context[key] = value[1:-1]
                            else:
                                try:
                                    shared_context[key] = bytes.fromhex(value).decode()
                                except ValueError:
                                    shared_context[key] = value
                        elif key == 'path_unquoted':
                            if 'path' not in shared_context:
                                shared_context['path'] = value.strip()
                        else:
                            shared_context[key] = value.strip()

        # Process AVC line
        for line in log_block.strip().split('\n'):
            if 'type=AVC' in line:
                # Start with shared context
                parsed_data.update(shared_context)

                # Extract AVC-specific fields
                for key, pattern in patterns["AVC"].items():
                    field_match = re.search(pattern, line)
                    if field_match:
                        if key == "comm" and len(field_match.groups()) > 1:
                            # Handle quoted/unquoted comm
                            parsed_data[key] = (field_match.group(1) or field_match.group(2)).strip()
                        elif key == 'path_unquoted':
                            if 'path' not in parsed_data:
                                parsed_data['path'] = field_match.group(1).strip()
                        else:
                            parsed_data[key] = field_match.group(1).strip()

                # Enhanced path resolution with priority system
                if 'path' not in parsed_data or not parsed_data['path']:
                    if shared_context.get('path'):
                        parsed_data['path'] = shared_context['path']
                    elif parsed_data.get('dev') and parsed_data.get('ino'):
                        parsed_data['path'] = f"dev:{parsed_data['dev']},inode:{parsed_data['ino']}"
                        parsed_data['path_type'] = 'dev_inode'
                    elif shared_context.get('dev') and shared_context.get('inode'):
                        parsed_data['path'] = f"dev:{shared_context['dev']},inode:{shared_context['inode']}"
                        parsed_data['path_type'] = 'dev_inode'
                else:
                    parsed_data['path_type'] = 'file_path'

                # Use comm as fallback for proctitle if needed
                if parsed_data.get('proctitle') in ["(null)", "null", "", None] and parsed_data.get('comm'):
                    parsed_data['proctitle'] = parsed_data['comm']

                break

        return parsed_data

    def print_enhanced_summary(self, parsed_log: dict, analysis: dict):
        """Print enhanced analysis summary"""
        self.console.print("\n")
        self.console.print(Rule("📊 SELinux Analysis Summary", style="blue"))

        # Create summary table
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Component", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")

        # Enhanced info with timestamp and more details
        if parsed_log.get("datetime_str"):
            table.add_row("Timestamp", parsed_log["datetime_str"])

        table.add_row("Process", parsed_log.get("comm", "Unknown"))
        table.add_row("PID", parsed_log.get("pid", "Unknown"))

        if parsed_log.get("exe"):
            table.add_row("Executable", parsed_log["exe"])

        table.add_row("Permission Denied", parsed_log.get("permission", "Unknown"))
        table.add_row("Target Class", parsed_log.get("tclass", "Unknown"))
        table.add_row("Source Context", parsed_log.get("scontext", "Unknown"))
        table.add_row("Target Context", parsed_log.get("tcontext", "Unknown"))

        if parsed_log.get("path"):
            path_display = parsed_log["path"]
            if parsed_log.get("path_type") == "dev_inode":
                path_display += " (device+inode)"
            table.add_row("File Path", path_display)

        if parsed_log.get("cwd"):
            table.add_row("Working Directory", parsed_log["cwd"])

        if parsed_log.get("dest_port"):
            table.add_row("Target Port", parsed_log["dest_port"])

        if parsed_log.get("permissive"):
            mode = "Permissive" if parsed_log["permissive"] == "1" else "Enforcing"
            table.add_row("SELinux Mode", mode)

        self.console.print(table)

        # Analysis results
        self.console.print("\n")
        self.console.print(Rule("🔍 Root Cause Analysis", style="yellow"))

        cause_panel = Panel(
            analysis.get("explanation", "No explanation available"),
            title="[bold red]Problem Identified[/bold red]",
            border_style="red"
        )
        self.console.print(cause_panel)

        # Solution
        self.console.print("\n")
        self.console.print(Rule("🛠️ Recommended Solution", style="green"))

        solution_text = f"**Solution Type**: {analysis.get('solution', 'Unknown')}\n"
        solution_text += f"**Confidence**: {analysis.get('confidence', 'Unknown')}\n"
        solution_text += f"**Method**: {analysis.get('method', 'MCP Analysis')}"

        solution_panel = Panel(
            solution_text,
            title="[bold green]Recommended Fix[/bold green]",
            border_style="green"
        )
        self.console.print(solution_panel)

        # Commands
        if analysis.get("commands"):
            self.console.print("\n")
            self.console.print(Rule("⚡ Commands to Execute", style="cyan"))

            for i, cmd in enumerate(analysis["commands"], 1):
                cmd_syntax = Syntax(cmd, "bash", theme="monokai", line_numbers=False)
                cmd_panel = Panel(
                    cmd_syntax,
                    title=f"[bold cyan]Step {i}[/bold cyan]",
                    border_style="cyan"
                )
                self.console.print(cmd_panel)

    async def interactive_analysis(self):
        """Interactive analysis mode with enhanced features"""
        self.console.print(Panel.fit(
            "[bold blue]🔒 SELinux AI Troubleshooter - Enhanced Edition[/bold blue]\n"
            "[cyan]Powered by Advanced Analysis + Heuristics[/cyan]",
            border_style="blue"
        ))

        # Start MCP session if enabled
        if self.mcp_enabled:
            await self.start_mcp_session()

        self.console.print("\n[yellow]📝 Paste your SELinux audit log below.[/yellow]")
        self.console.print("[dim]Press Ctrl+D when finished, or 'quit' to exit[/dim]\n")

        try:
            lines = []
            for line in sys.stdin:
                line = line.strip()
                if line.lower() == 'quit':
                    return
                lines.append(line)

            if not lines:
                self.console.print("[red]No input provided.[/red]")
                return

            avc_log = '\n'.join(lines)

            # Parse the log
            self.console.print("🔄 Parsing audit log...")
            parsed_log = self.parse_audit_log(avc_log)

            if not parsed_log:
                self.console.print("[red]❌ Could not parse the audit log.[/red]")
                return

            # Get system context (optional enhancement)
            system_context = ""
            try:
                result = subprocess.run(["sestatus"], capture_output=True, text=True, timeout=5)
                system_context = result.stdout
            except:
                pass

            # Analyze with MCP
            self.console.print("🧠 Analyzing with AI + Knowledge Base...")
            analysis = await self.analyze_with_mcp(avc_log, parsed_log, system_context)

            # Display results
            self.print_enhanced_summary(parsed_log, analysis)

            # Additional tools menu
            await self.additional_analysis_menu(parsed_log, avc_log)

        except KeyboardInterrupt:
            self.console.print("\n[yellow]Analysis cancelled.[/yellow]")
        except Exception as e:
            self.console.print(f"[red]❌ Error during analysis: {e}[/red]")

    async def additional_analysis_menu(self, parsed_log: dict, avc_log: str):
        """Additional analysis options menu"""
        if not self.mcp_enabled:
            return

        self.console.print("\n")
        self.console.print(Rule("🔧 Additional Analysis Tools", style="magenta"))

        options = [
            "1. Search SELinux Policy",
            "2. Find Relevant Booleans",
            "3. Audit2Allow Analysis",
            "4. Search Knowledge Base",
            "5. Exit"
        ]

        for option in options:
            self.console.print(f"  {option}")

        try:
            choice = input("\nSelect option (1-5): ").strip()

            if choice == "1":
                await self.policy_search_interactive(parsed_log)
            elif choice == "2":
                await self.boolean_search_interactive(parsed_log)
            elif choice == "3":
                result = await self.audit2allow_check(avc_log)
                self.console.print(Panel(result, title="Audit2Allow Analysis", border_style="blue"))
            elif choice == "4":
                await self.knowledge_search_interactive(parsed_log)
            elif choice == "5":
                return

        except (KeyboardInterrupt, EOFError):
            return

    async def policy_search_interactive(self, parsed_log: dict):
        """Interactive policy search"""
        self.console.print("\n[cyan]🔍 SELinux Policy Search[/cyan]")

        scontext = parsed_log.get("scontext", "")
        tcontext = parsed_log.get("tcontext", "")

        source_type = scontext.split(':')[2] if ':' in scontext else ""
        target_type = tcontext.split(':')[2] if ':' in tcontext else ""

        result = await self.search_policy(
            source_type=source_type,
            target_type=target_type,
            object_class=parsed_log.get("tclass", ""),
            permission=parsed_log.get("permission", "")
        )

        self.console.print(Panel(result, title="Policy Search Results", border_style="green"))

    async def boolean_search_interactive(self, parsed_log: dict):
        """Interactive boolean search"""
        self.console.print("\n[cyan]🔘 SELinux Boolean Search[/cyan]")

        comm = parsed_log.get("comm", "")
        result = await self.get_relevant_booleans(service=comm)

        self.console.print(Panel(result, title="Relevant Booleans", border_style="yellow"))

    async def knowledge_search_interactive(self, parsed_log: dict):
        """Interactive knowledge base search"""
        self.console.print("\n[cyan]📚 Knowledge Base Search[/cyan]")

        # Auto-generate query from parsed log
        query_parts = []
        if parsed_log.get("comm"):
            query_parts.append(parsed_log["comm"])
        if parsed_log.get("tclass"):
            query_parts.append(parsed_log["tclass"])
        if parsed_log.get("permission"):
            query_parts.append(parsed_log["permission"])

        auto_query = " ".join(query_parts)

        self.console.print(f"[dim]Auto-generated query: {auto_query}[/dim]")
        query = input("Enter search query (or press Enter to use auto-generated): ").strip()

        if not query:
            query = auto_query

        if query:
            result = await self.search_knowledge_base(query)
            self.console.print(Panel(result, title=f"Knowledge Search: {query}", border_style="blue"))

    async def cleanup(self):
        """Cleanup MCP session"""
        try:
            if self.session:
                await self.session.close()
        except:
            pass

        try:
            if self.session_cm:
                await self.session_cm.__aexit__(None, None, None)
        except:
            pass

        self.session = None
        self.session_cm = None

async def main():
    """Main async entry point"""
    client = SELinuxMCPClient()

    try:
        await client.interactive_analysis()
    finally:
        await client.cleanup()

def sync_main():
    """Synchronous wrapper for async main"""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nGoodbye!")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    sync_main()