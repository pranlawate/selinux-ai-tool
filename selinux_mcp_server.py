#!/usr/bin/env python3
"""
SELinux MCP Server - Advanced troubleshooting with local LLM and RAG
Integrates with existing ChromaDB knowledge base and Ollama setup
"""

import asyncio
import json
import subprocess
import re
import os
import sys
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

# MCP imports
from mcp.server.models import InitializationOptions
from mcp.server import NotificationOptions, Server
from mcp.types import (
    Resource, Tool, TextContent, ImageContent, EmbeddedResource, LoggingLevel
)
import mcp.types as types

# LangChain imports (your existing setup)
from langchain_ollama import OllamaLLM, OllamaEmbeddings
from langchain_chroma import Chroma
from langchain.prompts import ChatPromptTemplate
from langchain.schema.output_parser import StrOutputParser

@dataclass
class SELinuxContext:
    """Represents SELinux context information"""
    user: str
    role: str
    type: str
    level: str

    @classmethod
    def from_string(cls, context_str: str) -> 'SELinuxContext':
        parts = context_str.split(':')
        return cls(
            user=parts[0] if len(parts) > 0 else "",
            role=parts[1] if len(parts) > 1 else "",
            type=parts[2] if len(parts) > 2 else "",
            level=parts[3] if len(parts) > 3 else ""
        )

class SELinuxMCPServer:
    def __init__(self):
        self.server = Server("selinux-troubleshooter")
        self.persist_directory = "./chroma_db"
        self.setup_llm_and_rag()
        self.setup_tools()
        self.setup_resources()

    def setup_llm_and_rag(self):
        """Initialize LLM and RAG components"""
        try:
            print("Initializing LLM...")

            # Try to setup RAG components (optional)
            self.vectorstore = None
            self.retriever = None
            try:
                print("Attempting to initialize RAG components...")
                self.embeddings = OllamaEmbeddings(model="nomic-embed-text")
                self.vectorstore = Chroma(
                    persist_directory=self.persist_directory,
                    embedding_function=self.embeddings
                )
                self.retriever = self.vectorstore.as_retriever()
                print("RAG components initialized successfully")
            except Exception as e:
                print(f"RAG components not available: {e}")
                print("Continuing without knowledge base...")

            # Try CodeLlama first, fallback to available models
            try:
                self.llm = OllamaLLM(model="codellama:13b-instruct")
                print("Using CodeLlama 13B-Instruct for SELinux analysis")
            except Exception:
                try:
                    self.llm = OllamaLLM(model="llama3")
                    print("Using Llama3 for SELinux analysis")
                except Exception:
                    self.llm = OllamaLLM(model="llama3.2:3b")
                    print("Using Llama3.2 3B for SELinux analysis")

            # SELinux-specific prompt templates
            self.context_analysis_template = """
            SELINUX CONTEXT ANALYSIS:

            KNOWLEDGE BASE CONTEXT:
            {rag_context}

            SYSTEM CONTEXT:
            {system_context}

            SOURCE CONTEXT: {scontext}
            TARGET CONTEXT: {tcontext}
            TARGET CLASS: {tclass}
            DENIED PERMISSION: {permission}

            TASK: Analyze this SELinux denial and provide:
            1. Root cause analysis
            2. Specific solution (boolean OR file context change)
            3. Command to fix it
            4. Why this denial occurred

            RESPONSE FORMAT:
            CAUSE: [brief explanation]
            SOLUTION: [boolean OR context]
            COMMAND: [exact command to run]
            EXPLANATION: [detailed reasoning]
            """

            self.prompt = ChatPromptTemplate.from_template(self.context_analysis_template)
            self.chain = self.prompt | self.llm | StrOutputParser()

        except Exception as e:
            print(f"Error setting up LLM/RAG: {e}")
            sys.exit(1)

    def setup_tools(self):
        """Register MCP tools"""

        @self.server.list_tools()
        async def handle_list_tools() -> list[Tool]:
            return [
                Tool(
                    name="analyze_avc_denial",
                    description="Analyze SELinux AVC denial with RAG-enhanced reasoning",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "avc_log": {"type": "string", "description": "Raw AVC denial log"},
                            "parsed_log": {"type": "object", "description": "Parsed AVC components"},
                            "system_context": {"type": "string", "description": "Additional system context"}
                        },
                        "required": ["avc_log"]
                    }
                ),
                Tool(
                    name="search_selinux_policy",
                    description="Search SELinux policy using sesearch",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "source_type": {"type": "string", "description": "Source type to search"},
                            "target_type": {"type": "string", "description": "Target type to search"},
                            "object_class": {"type": "string", "description": "Object class to search"},
                            "permission": {"type": "string", "description": "Permission to search"}
                        },
                        "required": []
                    }
                ),
                Tool(
                    name="get_selinux_booleans",
                    description="Get SELinux booleans related to a service or context",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "service": {"type": "string", "description": "Service name to search booleans for"},
                            "pattern": {"type": "string", "description": "Pattern to match boolean names"}
                        },
                        "required": []
                    }
                ),
                Tool(
                    name="audit2allow_analysis",
                    description="Generate policy modules using audit2allow",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "avc_log": {"type": "string", "description": "AVC denial log to analyze"}
                        },
                        "required": ["avc_log"]
                    }
                ),
                Tool(
                    name="get_file_context",
                    description="Get current file context and suggest correct context",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "file_path": {"type": "string", "description": "File path to analyze"},
                            "process_context": {"type": "string", "description": "Process context trying to access"}
                        },
                        "required": ["file_path"]
                    }
                ),
                Tool(
                    name="rag_knowledge_search",
                    description="Search SELinux knowledge base for relevant information",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {"type": "string", "description": "Search query for knowledge base"}
                        },
                        "required": ["query"]
                    }
                )
            ]

        @self.server.call_tool()
        async def handle_call_tool(name: str, arguments: dict) -> list[types.TextContent]:
            """Handle tool execution"""

            if name == "analyze_avc_denial":
                return await self.analyze_avc_denial(arguments)
            elif name == "search_selinux_policy":
                return await self.search_selinux_policy(arguments)
            elif name == "get_selinux_booleans":
                return await self.get_selinux_booleans(arguments)
            elif name == "audit2allow_analysis":
                return await self.audit2allow_analysis(arguments)
            elif name == "get_file_context":
                return await self.get_file_context(arguments)
            elif name == "rag_knowledge_search":
                return await self.rag_knowledge_search(arguments)
            else:
                raise ValueError(f"Unknown tool: {name}")

    def setup_resources(self):
        """Setup MCP resources"""

        @self.server.list_resources()
        async def handle_list_resources() -> list[Resource]:
            return [
                Resource(
                    uri="selinux://policy/current",
                    name="Current SELinux Policy",
                    description="Information about the currently loaded SELinux policy",
                    mimeType="text/plain"
                ),
                Resource(
                    uri="selinux://booleans/all",
                    name="SELinux Booleans",
                    description="List of all SELinux booleans and their states",
                    mimeType="text/plain"
                ),
                Resource(
                    uri="selinux://knowledge/base",
                    name="SELinux Knowledge Base",
                    description="Local SELinux troubleshooting knowledge base",
                    mimeType="text/plain"
                )
            ]

        @self.server.read_resource()
        async def handle_read_resource(uri: str) -> str:
            if uri == "selinux://policy/current":
                return await self.get_current_policy_info()
            elif uri == "selinux://booleans/all":
                return await self.get_all_booleans()
            elif uri == "selinux://knowledge/base":
                return await self.get_knowledge_base_summary()
            else:
                raise ValueError(f"Unknown resource: {uri}")

    # Tool implementations
    async def analyze_avc_denial(self, args: dict) -> list[types.TextContent]:
        """Main AVC denial analysis with RAG enhancement"""
        try:
            avc_log = args.get("avc_log", "")
            parsed_log = args.get("parsed_log", {})
            system_context = args.get("system_context", "")

            # Parse AVC log if not already parsed
            if not parsed_log:
                parsed_log = self.parse_avc_log(avc_log)

            # Get RAG context if available
            rag_context = ""
            if self.retriever:
                rag_query = f"SELinux denial {parsed_log.get('scontext', '')} {parsed_log.get('tcontext', '')} {parsed_log.get('tclass', '')}"
                rag_docs = self.retriever.invoke(rag_query)
                rag_context = "\n".join([doc.page_content for doc in rag_docs[:3]])
            else:
                rag_context = "Knowledge base not available - using built-in SELinux knowledge"

            # Enhanced analysis using LLM
            analysis = self.chain.invoke({
                "rag_context": rag_context,
                "system_context": system_context,
                "scontext": parsed_log.get("scontext", ""),
                "tcontext": parsed_log.get("tcontext", ""),
                "tclass": parsed_log.get("tclass", ""),
                "permission": parsed_log.get("permission", "")
            })

            # Parse LLM response and format for MCP
            result = self.format_analysis_result(analysis, parsed_log)

            return [types.TextContent(
                type="text",
                text=json.dumps(result, indent=2)
            )]

        except Exception as e:
            return [types.TextContent(
                type="text",
                text=f"Error analyzing AVC denial: {str(e)}"
            )]

    async def search_selinux_policy(self, args: dict) -> list[types.TextContent]:
        """Search SELinux policy using sesearch"""
        try:
            cmd = ["sesearch"]

            if args.get("source_type"):
                cmd.extend(["-s", args["source_type"]])
            if args.get("target_type"):
                cmd.extend(["-t", args["target_type"]])
            if args.get("object_class"):
                cmd.extend(["-c", args["object_class"]])
            if args.get("permission"):
                cmd.extend(["-p", args["permission"]])

            cmd.append("-A")  # Allow rules

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            return [types.TextContent(
                type="text",
                text=f"Policy search results:\n{result.stdout}\n\nErrors (if any):\n{result.stderr}"
            )]

        except Exception as e:
            return [types.TextContent(
                type="text",
                text=f"Error searching policy: {str(e)}"
            )]

    async def get_selinux_booleans(self, args: dict) -> list[types.TextContent]:
        """Get SELinux booleans"""
        try:
            cmd = ["getsebool", "-a"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            booleans = result.stdout

            # Filter by service or pattern if provided
            if args.get("service") or args.get("pattern"):
                lines = booleans.split('\n')
                pattern = args.get("service", args.get("pattern", ""))
                filtered_lines = [line for line in lines if pattern.lower() in line.lower()]
                booleans = '\n'.join(filtered_lines)

            return [types.TextContent(
                type="text",
                text=f"SELinux Booleans:\n{booleans}"
            )]

        except Exception as e:
            return [types.TextContent(
                type="text",
                text=f"Error getting booleans: {str(e)}"
            )]

    async def audit2allow_analysis(self, args: dict) -> list[types.TextContent]:
        """Generate audit2allow recommendations"""
        try:
            avc_log = args.get("avc_log", "")

            # Write AVC log to temp file
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
                f.write(avc_log)
                temp_file = f.name

            # Run audit2allow
            cmd = ["audit2allow", "-i", temp_file]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            # Cleanup
            os.unlink(temp_file)

            return [types.TextContent(
                type="text",
                text=f"Audit2allow recommendations:\n{result.stdout}\n\nNotes:\n{result.stderr}"
            )]

        except Exception as e:
            return [types.TextContent(
                type="text",
                text=f"Error running audit2allow: {str(e)}"
            )]

    async def get_file_context(self, args: dict) -> list[types.TextContent]:
        """Analyze file context"""
        try:
            file_path = args.get("file_path", "")
            process_context = args.get("process_context", "")

            # Get current context
            cmd = ["ls", "-Z", file_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            current_context = result.stdout

            # Get expected context
            cmd = ["matchpathcon", file_path]
            expected_result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            expected_context = expected_result.stdout

            analysis = f"""
File Context Analysis:
File: {file_path}
Current: {current_context.strip()}
Expected: {expected_context.strip()}
Process: {process_context}

Context match: {'✓' if current_context in expected_context else '✗'}
"""

            return [types.TextContent(
                type="text",
                text=analysis
            )]

        except Exception as e:
            return [types.TextContent(
                type="text",
                text=f"Error analyzing file context: {str(e)}"
            )]

    async def rag_knowledge_search(self, args: dict) -> list[types.TextContent]:
        """Search the RAG knowledge base"""
        try:
            query = args.get("query", "")

            if not self.retriever:
                return [types.TextContent(
                    type="text",
                    text="Knowledge base not available. Please run build-kb.py to create the knowledge base."
                )]

            docs = self.retriever.invoke(query)

            results = []
            for i, doc in enumerate(docs[:5]):
                results.append(f"Result {i+1}:\n{doc.page_content}\n")

            return [types.TextContent(
                type="text",
                text=f"Knowledge base search results for '{query}':\n\n" + "\n".join(results)
            )]

        except Exception as e:
            return [types.TextContent(
                type="text",
                text=f"Error searching knowledge base: {str(e)}"
            )]

    # Helper methods
    def parse_avc_log(self, log: str) -> dict:
        """Parse AVC log (your existing logic)"""
        patterns = {
            "permission": r"denied\s+\{ ([^}]+) \}",
            "pid": r"pid=(\S+)",
            "comm": r"comm=\"([^\"]+)\"",
            "scontext": r"scontext=(\S+)",
            "tcontext": r"tcontext=(\S+)",
            "tclass": r"tclass=(\S+)",
            "path": r"path=\"([^\"]+)\""
        }

        parsed = {}
        for key, pattern in patterns.items():
            match = re.search(pattern, log)
            if match:
                parsed[key] = match.group(1)

        return parsed

    def format_analysis_result(self, llm_response: str, parsed_log: dict) -> dict:
        """Format LLM analysis into structured response"""
        # Parse LLM response
        lines = llm_response.split('\n')
        result = {
            "cause": "",
            "solution": "",
            "commands": [],
            "explanation": "",
            "confidence": "medium"
        }

        for line in lines:
            if line.startswith("CAUSE:"):
                result["cause"] = line.replace("CAUSE:", "").strip()
            elif line.startswith("SOLUTION:"):
                result["solution"] = line.replace("SOLUTION:", "").strip()
            elif line.startswith("COMMAND:"):
                cmd = line.replace("COMMAND:", "").strip()
                if cmd:
                    result["commands"].append(cmd)
            elif line.startswith("EXPLANATION:"):
                result["explanation"] = line.replace("EXPLANATION:", "").strip()

        return result

    async def get_current_policy_info(self) -> str:
        """Get current SELinux policy information"""
        try:
            cmd = ["sestatus"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.stdout
        except Exception as e:
            return f"Error getting policy info: {e}"

    async def get_all_booleans(self) -> str:
        """Get all SELinux booleans"""
        try:
            cmd = ["getsebool", "-a"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result.stdout
        except Exception as e:
            return f"Error getting booleans: {e}"

    async def get_knowledge_base_summary(self) -> str:
        """Get knowledge base summary"""
        try:
            # Query the vector store for general info
            docs = self.vectorstore.similarity_search("SELinux introduction overview", k=3)
            summary = "\n".join([doc.page_content[:500] + "..." for doc in docs])
            return f"Knowledge Base Summary:\n{summary}"
        except Exception as e:
            return f"Error accessing knowledge base: {e}"

    async def run_server(self):
        """Run the MCP server"""
        from mcp.server.stdio import stdio_server

        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="selinux-troubleshooter",
                    server_version="1.0.0",
                    capabilities=self.server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )

if __name__ == "__main__":
    print("Starting SELinux MCP Server...")
    server = SELinuxMCPServer()
    asyncio.run(server.run_server())