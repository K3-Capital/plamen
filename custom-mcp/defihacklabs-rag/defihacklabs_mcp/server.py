"""
DeFiHackLabs RAG MCP Server

Provides semantic search over DeFiHackLabs exploit database.
"""

import asyncio
from pathlib import Path
from typing import Any, List
import chromadb
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# Paths
DATA_DIR = Path(__file__).parent.parent / "data"
CHROMA_DIR = DATA_DIR / "chroma_db"
DEFIHACKLABS_DIR = DATA_DIR / "DeFiHackLabs"

# Initialize server
server = Server("defihacklabs-rag")

# ChromaDB client (initialized lazily)
_client = None
_collection = None


def get_collection():
    """Get or create the ChromaDB collection."""
    global _client, _collection
    if _collection is None:
        _client = chromadb.PersistentClient(path=str(CHROMA_DIR))
        _collection = _client.get_collection("exploits")
    return _collection


@server.list_tools()
async def list_tools() -> list[Tool]:
    """List available tools."""
    return [
        Tool(
            name="search_exploits",
            description="""
Semantic search across DeFiHackLabs exploit PoC database.
Returns exploits similar to your query, including code snippets.

Use for: Finding similar real-world exploits with working PoC code.

Args:
    query: Describe what you're looking for (e.g., "reentrancy with callback during transfer")
    limit: Number of results (default 5)
    category: Filter by category (optional)
""",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query describing the exploit pattern"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Number of results",
                        "default": 5
                    },
                    "category": {
                        "type": "string",
                        "description": "Filter by category",
                        "enum": ["reentrancy", "oracle-manipulation", "flash-loan", 
                                "access-control", "governance", "liquidation",
                                "first-depositor", "signature", "arithmetic", "front-running", "other"]
                    }
                },
                "required": ["query"]
            }
        ),
        Tool(
            name="search_by_category",
            description="""
Find exploits by attack category.

Categories: reentrancy, oracle-manipulation, flash-loan, access-control,
governance, liquidation, first-depositor, signature, arithmetic, front-running

Args:
    category: Attack category
    limit: Number of results
""",
            inputSchema={
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "description": "Attack category"
                    },
                    "limit": {
                        "type": "integer",
                        "default": 5
                    }
                },
                "required": ["category"]
            }
        ),
        Tool(
            name="get_exploit_code",
            description="""
Get the full source code of a specific exploit PoC.

Args:
    filename: The exploit filename (e.g., "Beanstalk_exp.sol")
""",
            inputSchema={
                "type": "object",
                "properties": {
                    "filename": {
                        "type": "string",
                        "description": "Exploit filename"
                    }
                },
                "required": ["filename"]
            }
        ),
        Tool(
            name="search_by_protocol",
            description="""
Find exploits targeting a specific protocol.

Args:
    protocol: Protocol name (e.g., "Curve", "Aave", "Compound")
    limit: Number of results
""",
            inputSchema={
                "type": "object",
                "properties": {
                    "protocol": {
                        "type": "string",
                        "description": "Protocol name"
                    },
                    "limit": {
                        "type": "integer",
                        "default": 5
                    }
                },
                "required": ["protocol"]
            }
        ),
        Tool(
            name="list_exploits",
            description="""
List all available exploits, optionally filtered.

Args:
    category: Filter by category (optional)
    limit: Maximum results (default 20)
""",
            inputSchema={
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string"
                    },
                    "limit": {
                        "type": "integer",
                        "default": 20
                    }
                }
            }
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle tool calls."""
    
    try:
        collection = get_collection()
    except Exception as e:
        return [TextContent(
            type="text",
            text=f"Error: Database not initialized. Run `python indexer.py` first.\nDetails: {e}"
        )]
    
    if name == "search_exploits":
        query = arguments["query"]
        limit = arguments.get("limit", 5)
        category = arguments.get("category")
        
        # Build where filter
        where = {"category": category} if category else None
        
        results = collection.query(
            query_texts=[query],
            n_results=limit,
            where=where,
        )
        
        if not results['documents'][0]:
            return [TextContent(type="text", text="No exploits found matching your query.")]
        
        output = f"## DeFiHackLabs: Exploits matching '{query}'\n\n"
        
        for i, (doc, meta) in enumerate(zip(results['documents'][0], results['metadatas'][0]), 1):
            output += f"### {i}. {meta.get('protocol', 'Unknown')} Exploit\n"
            output += f"**File**: `{meta.get('filename', 'N/A')}`\n"
            output += f"**Category**: {meta.get('category', 'N/A')}\n"
            output += f"**Amount Lost**: {meta.get('amount_lost', 'N/A')}\n"
            output += f"**Date**: {meta.get('date', 'N/A')}\n"
            
            if meta.get('attack_vector'):
                output += f"**Attack Vector**: {meta['attack_vector']}\n"
            
            if meta.get('analysis_url'):
                output += f"**Analysis**: {meta['analysis_url']}\n"
            
            # Include code preview
            code_preview = doc.split("Code Preview:")[-1][:500] if "Code Preview:" in doc else ""
            if code_preview:
                output += f"\n```solidity\n{code_preview.strip()}...\n```\n"
            
            output += f"\n*Use `get_exploit_code(\"{meta.get('filename')}\")` for full code*\n\n---\n\n"
        
        return [TextContent(type="text", text=output)]
    
    elif name == "search_by_category":
        category = arguments["category"]
        limit = arguments.get("limit", 5)
        
        results = collection.query(
            query_texts=[category],
            n_results=limit,
            where={"category": category},
        )
        
        output = f"## {category.title()} Exploits from DeFiHackLabs\n\n"
        
        for i, meta in enumerate(results['metadatas'][0], 1):
            output += f"{i}. **{meta.get('protocol', 'Unknown')}** - {meta.get('amount_lost', 'N/A')} - `{meta.get('filename')}`\n"
            if meta.get('attack_vector'):
                output += f"   _{meta['attack_vector']}_\n"
        
        return [TextContent(type="text", text=output)]
    
    elif name == "get_exploit_code":
        filename = arguments["filename"]
        
        # Find the file
        poc_dir = DEFIHACKLABS_DIR / "src" / "test"
        matching_files = list(poc_dir.glob(f"**/{filename}"))
        
        if not matching_files:
            # Try partial match
            matching_files = list(poc_dir.glob(f"**/*{filename}*"))
        
        if not matching_files:
            return [TextContent(
                type="text",
                text=f"Exploit file not found: {filename}\n\nTry searching first with search_exploits() to find available files."
            )]
        
        filepath = matching_files[0]
        code = filepath.read_text(encoding='utf-8', errors='ignore')
        
        output = f"## {filename}\n\n"
        output += f"**Path**: `{filepath}`\n\n"
        output += f"```solidity\n{code}\n```"
        
        return [TextContent(type="text", text=output)]
    
    elif name == "search_by_protocol":
        protocol = arguments["protocol"]
        limit = arguments.get("limit", 5)
        
        results = collection.query(
            query_texts=[protocol],
            n_results=limit,
        )
        
        # Filter by protocol name in metadata
        filtered = []
        for doc, meta in zip(results['documents'][0], results['metadatas'][0]):
            if protocol.lower() in meta.get('protocol', '').lower():
                filtered.append((doc, meta))
        
        if not filtered:
            return [TextContent(type="text", text=f"No exploits found for protocol: {protocol}")]
        
        output = f"## {protocol} Exploits\n\n"
        
        for i, (doc, meta) in enumerate(filtered[:limit], 1):
            output += f"{i}. **{meta.get('protocol')}** ({meta.get('date', 'N/A')})\n"
            output += f"   Category: {meta.get('category')} | Lost: {meta.get('amount_lost', 'N/A')}\n"
            output += f"   File: `{meta.get('filename')}`\n\n"
        
        return [TextContent(type="text", text=output)]
    
    elif name == "list_exploits":
        category = arguments.get("category")
        limit = arguments.get("limit", 20)
        
        # Get all items (or filtered)
        where = {"category": category} if category else None
        
        results = collection.query(
            query_texts=["exploit hack attack"],  # Generic query to get all
            n_results=limit,
            where=where,
        )
        
        output = "## Available DeFiHackLabs Exploits\n\n"
        if category:
            output = f"## {category.title()} Exploits\n\n"
        
        output += "| Protocol | Category | Amount | File |\n"
        output += "|----------|----------|--------|------|\n"
        
        for meta in results['metadatas'][0]:
            output += f"| {meta.get('protocol', 'N/A')[:20]} | {meta.get('category', 'N/A')} | {meta.get('amount_lost', 'N/A')} | `{meta.get('filename', 'N/A')}` |\n"
        
        return [TextContent(type="text", text=output)]
    
    else:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]


async def main():
    """Run the MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
