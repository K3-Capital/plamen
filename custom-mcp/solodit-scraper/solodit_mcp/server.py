"""
Solodit MCP Server

Provides comprehensive access to locally-indexed Solodit vulnerability data.
"""

import asyncio
import json
from typing import Any
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Tool,
    TextContent,
)

from .database import (
    init_database,
    search_findings,
    search_by_category,
    get_finding_by_id,
    get_statistics,
    list_categories,
)

# Initialize server
server = Server("solodit-local")


@server.list_tools()
async def list_tools() -> list[Tool]:
    """List available tools."""
    return [
        Tool(
            name="search_vulnerabilities",
            description="""
Search Solodit vulnerability database with full-text search.
Returns multiple relevant findings (not just one page).

Use for: Finding similar exploits, researching vulnerability patterns.

Args:
    query: Search query (e.g., "reentrancy", "oracle manipulation", "flash loan governance")
    limit: Number of results (default 10, max 50)
    severity: Filter by severity (Critical, High, Medium, Low)
    category: Filter by category (reentrancy, oracle-manipulation, access-control, etc.)
    protocol_type: Filter by protocol type (DEX, Lending, Vault, Bridge, etc.)
""",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Number of results (default 10)",
                        "default": 10
                    },
                    "severity": {
                        "type": "string",
                        "description": "Filter by severity",
                        "enum": ["Critical", "High", "Medium", "Low", "Info"]
                    },
                    "category": {
                        "type": "string",
                        "description": "Filter by vulnerability category"
                    },
                    "protocol_type": {
                        "type": "string",
                        "description": "Filter by protocol type",
                        "enum": ["DEX", "Lending", "Vault", "Bridge", "Staking", "Governance", "NFT", "Token", "Other"]
                    }
                },
                "required": ["query"]
            }
        ),
        Tool(
            name="search_by_category",
            description="""
Search vulnerabilities by category. Returns multiple findings sorted by severity.

Categories: reentrancy, oracle-manipulation, access-control, flash-loan, dos, 
front-running, arithmetic, governance, liquidation, signature, upgrade, 
initialization, erc4626, centralization, other

Args:
    category: Vulnerability category
    limit: Number of results (default 10)
    severity: Filter by severity
""",
            inputSchema={
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "description": "Vulnerability category"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Number of results",
                        "default": 10
                    },
                    "severity": {
                        "type": "string",
                        "description": "Filter by severity",
                        "enum": ["Critical", "High", "Medium", "Low"]
                    }
                },
                "required": ["category"]
            }
        ),
        Tool(
            name="get_finding_details",
            description="""
Get full details for a specific vulnerability finding by ID.
Includes code snippets, impact, and recommendations.

Args:
    finding_id: The finding ID from search results
""",
            inputSchema={
                "type": "object",
                "properties": {
                    "finding_id": {
                        "type": "string",
                        "description": "Finding ID"
                    }
                },
                "required": ["finding_id"]
            }
        ),
        Tool(
            name="list_categories",
            description="""
List all vulnerability categories with counts.
Useful for understanding what's available in the database.
""",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="get_statistics",
            description="""
Get database statistics: total findings, breakdown by severity and category.
""",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="search_by_protocol_type",
            description="""
Search vulnerabilities by protocol type (DEX, Lending, Vault, etc.).

Args:
    protocol_type: Type of protocol
    limit: Number of results
    severity: Filter by severity
    category: Also filter by vulnerability category
""",
            inputSchema={
                "type": "object",
                "properties": {
                    "protocol_type": {
                        "type": "string",
                        "description": "Protocol type",
                        "enum": ["DEX", "Lending", "Vault", "Bridge", "Staking", "Governance", "NFT", "Token", "Other"]
                    },
                    "limit": {
                        "type": "integer",
                        "default": 10
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["Critical", "High", "Medium", "Low"]
                    },
                    "category": {
                        "type": "string"
                    }
                },
                "required": ["protocol_type"]
            }
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle tool calls."""
    
    if name == "search_vulnerabilities":
        results = await search_findings(
            query=arguments["query"],
            limit=arguments.get("limit", 10),
            severity=arguments.get("severity"),
            category=arguments.get("category"),
            protocol_type=arguments.get("protocol_type"),
        )
        
        if not results:
            return [TextContent(
                type="text",
                text=f"No findings found for query: {arguments['query']}"
            )]
        
        # Format results for readability
        output = f"## Solodit Search Results: '{arguments['query']}'\n\n"
        output += f"Found {len(results)} relevant findings:\n\n"
        
        for i, finding in enumerate(results, 1):
            output += f"### {i}. [{finding['severity']}] {finding['title']}\n"
            output += f"**Category**: {finding['category']} | **Protocol**: {finding.get('protocol', 'N/A')}\n"
            output += f"**ID**: `{finding['id']}`\n\n"
            
            if finding.get('description'):
                desc = finding['description'][:500] + "..." if len(finding.get('description', '')) > 500 else finding.get('description', '')
                output += f"{desc}\n\n"
            
            if finding.get('code_snippet'):
                snippet = finding['code_snippet'][:300] + "..." if len(finding.get('code_snippet', '')) > 300 else finding.get('code_snippet', '')
                output += f"```solidity\n{snippet}\n```\n\n"
            
            output += f"[Full details]({finding.get('url', 'N/A')})\n\n---\n\n"
        
        return [TextContent(type="text", text=output)]
    
    elif name == "search_by_category":
        results = await search_by_category(
            category=arguments["category"],
            limit=arguments.get("limit", 10),
            severity=arguments.get("severity"),
        )
        
        if not results:
            return [TextContent(
                type="text",
                text=f"No findings found for category: {arguments['category']}"
            )]
        
        output = f"## {arguments['category'].title()} Vulnerabilities\n\n"
        output += f"Found {len(results)} findings:\n\n"
        
        for i, finding in enumerate(results, 1):
            output += f"### {i}. [{finding['severity']}] {finding['title']}\n"
            output += f"**Protocol**: {finding.get('protocol', 'N/A')} ({finding.get('protocol_type', 'N/A')})\n"
            
            if finding.get('impact'):
                impact = finding['impact'][:200] + "..." if len(finding.get('impact', '')) > 200 else finding.get('impact', '')
                output += f"**Impact**: {impact}\n"
            
            output += f"\n---\n\n"
        
        return [TextContent(type="text", text=output)]
    
    elif name == "get_finding_details":
        finding = await get_finding_by_id(arguments["finding_id"])
        
        if not finding:
            return [TextContent(
                type="text",
                text=f"Finding not found: {arguments['finding_id']}"
            )]
        
        output = f"## {finding['title']}\n\n"
        output += f"**Severity**: {finding['severity']}\n"
        output += f"**Category**: {finding['category']}\n"
        output += f"**Protocol**: {finding.get('protocol', 'N/A')} ({finding.get('protocol_type', 'N/A')})\n"
        output += f"**Audit Firm**: {finding.get('audit_firm', 'N/A')}\n"
        output += f"**Date**: {finding.get('audit_date', 'N/A')}\n\n"
        
        if finding.get('description'):
            output += f"### Description\n{finding['description']}\n\n"
        
        if finding.get('impact'):
            output += f"### Impact\n{finding['impact']}\n\n"
        
        if finding.get('code_snippet'):
            output += f"### Vulnerable Code\n```solidity\n{finding['code_snippet']}\n```\n\n"
        
        if finding.get('recommendation'):
            output += f"### Recommendation\n{finding['recommendation']}\n\n"
        
        if finding.get('tags'):
            output += f"**Tags**: {', '.join(finding['tags'])}\n\n"
        
        output += f"**URL**: {finding.get('url', 'N/A')}\n"
        
        return [TextContent(type="text", text=output)]
    
    elif name == "list_categories":
        categories = await list_categories()
        
        output = "## Vulnerability Categories\n\n"
        output += "| Category | Count |\n|----------|-------|\n"
        for cat in categories:
            output += f"| {cat['category']} | {cat['count']} |\n"
        
        return [TextContent(type="text", text=output)]
    
    elif name == "get_statistics":
        stats = await get_statistics()
        
        output = "## Solodit Database Statistics\n\n"
        output += f"**Total Findings**: {stats['total_findings']}\n"
        output += f"**Last Updated**: {stats['last_update']}\n\n"
        
        output += "### By Severity\n"
        for severity, count in stats['by_severity'].items():
            output += f"- {severity}: {count}\n"
        
        output += "\n### Top Categories\n"
        for category, count in stats['top_categories'].items():
            output += f"- {category}: {count}\n"
        
        return [TextContent(type="text", text=output)]
    
    elif name == "search_by_protocol_type":
        results = await search_findings(
            query=arguments["protocol_type"],
            limit=arguments.get("limit", 10),
            severity=arguments.get("severity"),
            category=arguments.get("category"),
            protocol_type=arguments["protocol_type"],
        )
        
        output = f"## {arguments['protocol_type']} Protocol Vulnerabilities\n\n"
        output += f"Found {len(results)} findings:\n\n"
        
        for i, finding in enumerate(results, 1):
            output += f"### {i}. [{finding['severity']}] {finding['title']}\n"
            output += f"**Category**: {finding['category']}\n\n"
        
        return [TextContent(type="text", text=output)]
    
    else:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]


async def main():
    """Run the MCP server."""
    # Initialize database on startup
    await init_database()
    
    # Run server
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
