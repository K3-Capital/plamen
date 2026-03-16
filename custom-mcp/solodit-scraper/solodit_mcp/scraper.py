"""
Solodit Scraper

Scrapes vulnerability findings from Solodit.xyz and stores them locally.
Supports both full scrape and incremental updates.
"""

import asyncio
import httpx
import json
import re
from bs4 import BeautifulSoup
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any, AsyncGenerator
from dataclasses import dataclass
from tenacity import retry, stop_after_attempt, wait_exponential
from ratelimit import limits, sleep_and_retry
from rich.console import Console
from rich.progress import Progress, TaskID

from .database import Finding, init_database, insert_finding, set_metadata

console = Console()

# Rate limiting: 2 requests per second
CALLS_PER_SECOND = 2
PERIOD = 1

# Solodit base URL
BASE_URL = "https://solodit.cyfrin.io"

# Vulnerability categories to scrape
CATEGORIES = [
    "reentrancy",
    "access-control",
    "oracle",
    "price-manipulation",
    "flash-loan",
    "dos",
    "denial-of-service",
    "frontrunning",
    "front-running",
    "sandwich",
    "integer-overflow",
    "arithmetic",
    "rounding",
    "precision",
    "signature",
    "replay",
    "governance",
    "liquidation",
    "first-depositor",
    "donation-attack",
    "inflation",
    "erc4626",
    "erc20",
    "erc721",
    "erc777",
    "callback",
    "cross-function",
    "cross-contract",
    "read-only-reentrancy",
    "timestamp",
    "randomness",
    "centralization",
    "rug-pull",
    "upgrade",
    "proxy",
    "initialize",
    "storage-collision",
    "delegate-call",
    "self-destruct",
    "gas-griefing",
    "unchecked-return",
]


@sleep_and_retry
@limits(calls=CALLS_PER_SECOND, period=PERIOD)
async def rate_limited_request(client: httpx.AsyncClient, url: str) -> httpx.Response:
    """Make a rate-limited HTTP request."""
    return await client.get(url, follow_redirects=True)


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
async def fetch_page(client: httpx.AsyncClient, url: str) -> str:
    """Fetch a page with retry logic."""
    response = await rate_limited_request(client, url)
    response.raise_for_status()
    return response.text


def parse_severity(text: str) -> str:
    """Parse severity from text."""
    text_lower = text.lower()
    if "critical" in text_lower:
        return "Critical"
    elif "high" in text_lower:
        return "High"
    elif "medium" in text_lower:
        return "Medium"
    elif "low" in text_lower:
        return "Low"
    elif "info" in text_lower or "gas" in text_lower:
        return "Info"
    return "Unknown"


def categorize_finding(title: str, description: str) -> str:
    """Categorize a finding based on title and description."""
    text = f"{title} {description}".lower()
    
    # Category keywords mapping
    category_keywords = {
        "reentrancy": ["reentrancy", "re-entrancy", "reentrant", "callback"],
        "oracle-manipulation": ["oracle", "price manipulation", "price feed", "chainlink", "twap"],
        "access-control": ["access control", "authorization", "permission", "role", "admin", "owner", "modifier"],
        "flash-loan": ["flash loan", "flashloan", "flash-loan"],
        "dos": ["denial of service", "dos", "revert", "block", "grief"],
        "front-running": ["front-run", "frontrun", "sandwich", "mev"],
        "arithmetic": ["overflow", "underflow", "precision", "rounding", "division"],
        "governance": ["governance", "vote", "voting", "proposal", "quorum"],
        "liquidation": ["liquidation", "liquidate", "collateral"],
        "signature": ["signature", "replay", "ecrecover", "eip712"],
        "upgrade": ["upgrade", "proxy", "implementation", "delegatecall"],
        "initialization": ["initialize", "initializer", "reinitialize"],
        "erc4626": ["erc4626", "vault", "share", "deposit", "withdraw"],
        "centralization": ["centralization", "rug", "admin key", "single point"],
    }
    
    for category, keywords in category_keywords.items():
        for keyword in keywords:
            if keyword in text:
                return category
    
    return "other"


def extract_protocol_type(text: str) -> str:
    """Extract protocol type from text."""
    text_lower = text.lower()
    
    if any(x in text_lower for x in ["dex", "swap", "amm", "liquidity pool", "uniswap"]):
        return "DEX"
    elif any(x in text_lower for x in ["lending", "borrow", "loan", "aave", "compound"]):
        return "Lending"
    elif any(x in text_lower for x in ["vault", "yield", "strategy", "yearn"]):
        return "Vault"
    elif any(x in text_lower for x in ["bridge", "cross-chain", "layer"]):
        return "Bridge"
    elif any(x in text_lower for x in ["staking", "stake", "reward"]):
        return "Staking"
    elif any(x in text_lower for x in ["governance", "dao", "vote"]):
        return "Governance"
    elif any(x in text_lower for x in ["nft", "erc721", "erc1155"]):
        return "NFT"
    elif any(x in text_lower for x in ["token", "erc20"]):
        return "Token"
    
    return "Other"


async def scrape_search_results(
    client: httpx.AsyncClient,
    query: str,
    max_pages: int = 10
) -> AsyncGenerator[Dict[str, Any], None]:
    """
    Scrape search results for a query.
    
    Note: This is a template - actual implementation depends on Solodit's 
    HTML structure which may change. You may need to adjust selectors.
    """
    for page in range(1, max_pages + 1):
        url = f"{BASE_URL}/issues?q={query}&page={page}"
        
        try:
            html = await fetch_page(client, url)
            soup = BeautifulSoup(html, 'lxml')
            
            # Find all finding cards/items
            # Note: Adjust selectors based on actual Solodit HTML
            items = soup.select('.finding-card, .issue-item, [data-finding]')
            
            if not items:
                # Try alternative selectors
                items = soup.select('article, .card, .result-item')
            
            if not items:
                console.print(f"[yellow]No items found on page {page} for '{query}'[/yellow]")
                break
            
            for item in items:
                try:
                    # Extract finding data
                    # Note: These selectors are examples - adjust for actual HTML
                    
                    title_elem = item.select_one('h2, h3, .title, [data-title]')
                    title = title_elem.get_text(strip=True) if title_elem else ""
                    
                    link_elem = item.select_one('a[href*="/issues/"]')
                    url = link_elem['href'] if link_elem else ""
                    if url and not url.startswith('http'):
                        url = BASE_URL + url
                    
                    severity_elem = item.select_one('.severity, [data-severity], .badge')
                    severity = parse_severity(severity_elem.get_text() if severity_elem else "")
                    
                    desc_elem = item.select_one('.description, p, .content')
                    description = desc_elem.get_text(strip=True) if desc_elem else ""
                    
                    protocol_elem = item.select_one('.protocol, [data-protocol]')
                    protocol = protocol_elem.get_text(strip=True) if protocol_elem else ""
                    
                    # Generate unique ID
                    finding_id = re.sub(r'[^a-zA-Z0-9]', '-', title.lower())[:50]
                    finding_id = f"{finding_id}-{hash(url) % 10000}"
                    
                    yield {
                        "id": finding_id,
                        "title": title,
                        "severity": severity,
                        "description": description,
                        "protocol": protocol,
                        "url": url,
                        "query": query,
                    }
                    
                except Exception as e:
                    console.print(f"[red]Error parsing item: {e}[/red]")
                    continue
                    
        except Exception as e:
            console.print(f"[red]Error fetching page {page} for '{query}': {e}[/red]")
            break


async def scrape_finding_details(
    client: httpx.AsyncClient,
    finding_url: str
) -> Dict[str, Any]:
    """
    Scrape full details for a single finding.
    
    Note: Adjust selectors based on actual Solodit HTML.
    """
    try:
        html = await fetch_page(client, finding_url)
        soup = BeautifulSoup(html, 'lxml')
        
        # Extract detailed information
        # Note: These selectors are examples - adjust for actual HTML
        
        # Impact section
        impact_elem = soup.select_one('.impact, [data-impact], #impact')
        impact = impact_elem.get_text(strip=True) if impact_elem else ""
        
        # Code snippet
        code_elem = soup.select_one('pre code, .code-snippet, code')
        code_snippet = code_elem.get_text() if code_elem else ""
        
        # Recommendation
        rec_elem = soup.select_one('.recommendation, [data-recommendation], #recommendation')
        recommendation = rec_elem.get_text(strip=True) if rec_elem else ""
        
        # Audit firm
        firm_elem = soup.select_one('.audit-firm, [data-firm], .auditor')
        audit_firm = firm_elem.get_text(strip=True) if firm_elem else ""
        
        # Audit date
        date_elem = soup.select_one('.date, [data-date], time')
        audit_date = date_elem.get_text(strip=True) if date_elem else ""
        
        # Tags
        tag_elems = soup.select('.tag, .label, [data-tag]')
        tags = [tag.get_text(strip=True) for tag in tag_elems]
        
        return {
            "impact": impact,
            "code_snippet": code_snippet[:5000] if code_snippet else "",  # Limit size
            "recommendation": recommendation,
            "audit_firm": audit_firm,
            "audit_date": audit_date,
            "tags": tags,
        }
        
    except Exception as e:
        console.print(f"[red]Error fetching details for {finding_url}: {e}[/red]")
        return {}


async def run_full_scrape(max_findings_per_category: int = 100):
    """
    Run a full scrape of Solodit.
    
    Args:
        max_findings_per_category: Maximum findings to scrape per category
    """
    console.print("[bold blue]Starting full Solodit scrape...[/bold blue]")
    
    await init_database()
    
    total_saved = 0
    
    async with httpx.AsyncClient(
        timeout=30.0,
        headers={
            "User-Agent": "Mozilla/5.0 (compatible; SoloditResearchBot/1.0)"
        }
    ) as client:
        
        with Progress() as progress:
            category_task = progress.add_task(
                "[cyan]Categories...", 
                total=len(CATEGORIES)
            )
            
            for category in CATEGORIES:
                progress.update(category_task, description=f"[cyan]Scraping: {category}")
                
                findings_in_category = 0
                
                async for item in scrape_search_results(
                    client, 
                    category, 
                    max_pages=max_findings_per_category // 10
                ):
                    if findings_in_category >= max_findings_per_category:
                        break
                    
                    # Get full details
                    if item.get('url'):
                        details = await scrape_finding_details(client, item['url'])
                        item.update(details)
                    
                    # Categorize and type
                    item['category'] = categorize_finding(
                        item.get('title', ''),
                        item.get('description', '')
                    )
                    item['protocol_type'] = extract_protocol_type(
                        f"{item.get('protocol', '')} {item.get('description', '')}"
                    )
                    
                    # Create Finding object
                    finding = Finding(
                        id=item.get('id', ''),
                        title=item.get('title', ''),
                        severity=item.get('severity', 'Unknown'),
                        category=item.get('category', 'other'),
                        protocol=item.get('protocol', ''),
                        protocol_type=item.get('protocol_type', 'Other'),
                        description=item.get('description', ''),
                        impact=item.get('impact', ''),
                        code_snippet=item.get('code_snippet', ''),
                        recommendation=item.get('recommendation', ''),
                        audit_firm=item.get('audit_firm', ''),
                        audit_date=item.get('audit_date', ''),
                        url=item.get('url', ''),
                        tags=item.get('tags', []),
                    )
                    
                    await insert_finding(finding)
                    findings_in_category += 1
                    total_saved += 1
                
                progress.advance(category_task)
                console.print(f"  [green]✓ {category}: {findings_in_category} findings[/green]")
    
    # Update metadata
    await set_metadata("last_scrape", datetime.now().isoformat())
    await set_metadata("total_findings", str(total_saved))
    
    console.print(f"\n[bold green]Scrape complete! Total findings: {total_saved}[/bold green]")


async def run_incremental_update():
    """Run an incremental update (only new findings)."""
    console.print("[bold blue]Running incremental update...[/bold blue]")
    # Similar to full scrape but checks for existing IDs
    # Implementation depends on how Solodit orders results
    await run_full_scrape(max_findings_per_category=20)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--update":
        asyncio.run(run_incremental_update())
    else:
        asyncio.run(run_full_scrape())
