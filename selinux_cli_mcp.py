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
        self.mcp_enabled = True

    async def start_mcp_session(self):
        """Start MCP session with SELinux server"""
        try:
            import os
            server_params = StdioServerParameters(
                command="python3",
                args=[os.path.join(os.path.dirname(__file__), "selinux_mcp_server.py")],
                env=None
            )

            # Store the context manager and enter it with timeout
            self.session_cm = stdio_client(server_params)
            read_stream, write_stream = await asyncio.wait_for(
                self.session_cm.__aenter__(), timeout=10.0
            )

            from mcp.client.session import ClientSession
            self.session = ClientSession(read_stream, write_stream)
            await asyncio.wait_for(self.session.initialize(), timeout=10.0)

            self.console.print("✅ MCP Server connected successfully", style="green")
            return True

        except Exception as e:
            self.console.print(f"⚠️ MCP Server connection failed: {e}", style="yellow")
            self.console.print("Falling back to basic analysis mode", style="yellow")
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
        """Fallback analysis using your existing logic"""
        scontext = parsed_log.get("scontext", "")
        tcontext = parsed_log.get("tcontext", "")
        tclass = parsed_log.get("tclass", "")
        permission = parsed_log.get("permission", "")

        # Your existing heuristic logic
        if "socket" in tclass:
            problem_type = "BOOLEAN"
            solution = f"{scontext.split(':')[2]}_connect" if scontext else "unknown_boolean"
            explanation = f"Socket operation denied. May need boolean: {solution}"
            commands = [f"setsebool -P {solution} on"]
        else:
            problem_type = "TCONTEXT_MISMATCH"
            solution = f"{scontext.split(':')[2]}_t" if scontext else "unknown_t"
            explanation = f"File context mismatch. Target should be: {solution}"
            path = parsed_log.get("path", "/unknown/path")
            commands = [
                f"semanage fcontext -a -t {solution} '{os.path.dirname(path)}(/.*)?'",
                f"restorecon -Rv {os.path.dirname(path)}"
            ]

        return {
            "cause": f"SELinux {problem_type.lower().replace('_', ' ')}",
            "solution": solution,
            "commands": commands,
            "explanation": explanation,
            "confidence": "low",
            "method": "fallback_heuristic"
        }

    def parse_audit_log(self, log_block: str) -> dict:
        """Parse audit log (your existing logic)"""
        parsed_data = {}
        patterns = {
            "AVC": {
                "permission": r"denied\s+\{ ([^}]+) \}",
                "pid": r"pid=(\S+)",
                "comm": r"comm=\"([^\"]+)\"",
                "scontext": r"scontext=(\S+)",
                "tcontext": r"tcontext=(\S+)",
                "tclass": r"tclass=(\S+)",
                "dest_port": r"dest=(\S+)"
            },
            "CWD": {"cwd": r"cwd=\"([^\"]+)\""},
            "PATH": {"path": r"name=\"([^\"]+)\""},
            "SYSCALL": {"syscall": r"syscall=([\w\d]+)", "exe": r"exe=\"([^\"]+)\""},
            "PROCTITLE": {"proctitle": r"proctitle=(\S+)"},
            "SOCKADDR": {"saddr": r"saddr=\{([^\}]+)\}"}
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

    def print_enhanced_summary(self, parsed_log: dict, analysis: dict):
        """Print enhanced analysis summary"""
        self.console.print("\n")
        self.console.print(Rule("📊 SELinux Analysis Summary", style="blue"))

        # Create summary table
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Component", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")

        # Basic info
        table.add_row("Process", parsed_log.get("comm", "Unknown"))
        table.add_row("PID", parsed_log.get("pid", "Unknown"))
        table.add_row("Permission Denied", parsed_log.get("permission", "Unknown"))
        table.add_row("Target Class", parsed_log.get("tclass", "Unknown"))
        table.add_row("Source Context", parsed_log.get("scontext", "Unknown"))
        table.add_row("Target Context", parsed_log.get("tcontext", "Unknown"))

        if parsed_log.get("path"):
            table.add_row("File Path", parsed_log["path"])

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
            "[bold blue]🔒 SELinux AI Troubleshooter - Enhanced MCP Edition[/bold blue]\n"
            "[cyan]Powered by Local LLM + RAG + MCP Tools[/cyan]",
            border_style="blue"
        ))

        # Start MCP session
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
        if self.session_cm and self.session:
            try:
                await self.session_cm.__aexit__(None, None, None)
            except:
                pass
        elif self.session:
            try:
                await self.session.close()
            except:
                pass

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