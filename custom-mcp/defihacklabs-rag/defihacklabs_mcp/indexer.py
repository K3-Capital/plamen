"""
DeFiHackLabs Indexer

Parses exploit PoC files and creates embeddings for semantic search.
"""

import os
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import chromadb
from chromadb.config import Settings
from rich.console import Console
from rich.progress import Progress

console = Console()

# Paths
DATA_DIR = Path(__file__).parent.parent / "data"
DEFIHACKLABS_DIR = DATA_DIR / "DeFiHackLabs"
CHROMA_DIR = DATA_DIR / "chroma_db"


@dataclass
class Exploit:
    """Represents a parsed exploit PoC."""
    filename: str
    filepath: str
    protocol: str
    date: str
    amount_lost: str
    attack_vector: str
    description: str
    code: str
    category: str
    tx_hash: Optional[str] = None
    analysis_url: Optional[str] = None


def parse_exploit_file(filepath: Path) -> Optional[Exploit]:
    """Parse a Solidity exploit file and extract metadata."""
    try:
        content = filepath.read_text(encoding='utf-8', errors='ignore')
        
        # Extract metadata from comments
        protocol = ""
        date = ""
        amount = ""
        attack_vector = ""
        tx_hash = ""
        analysis_url = ""
        
        # Look for header comment block
        header_match = re.search(r'/\*[\s\S]*?\*/', content)
        if header_match:
            header = header_match.group()
            
            # Extract protocol name from filename or content
            protocol_match = re.search(r'(?:Exploit|Attack|Hack):\s*([^\n-]+)', header)
            if protocol_match:
                protocol = protocol_match.group(1).strip()
            else:
                # Use filename
                protocol = filepath.stem.replace('_exp', '').replace('_', ' ')
            
            # Extract date
            date_match = re.search(r'(\d{4}[-/]\d{2}[-/]\d{2}|\w+\s+\d{1,2},?\s+\d{4})', header)
            if date_match:
                date = date_match.group(1)
            
            # Extract amount lost
            amount_match = re.search(r'\$[\d,]+(?:\.\d+)?[MKB]?|\d+(?:,\d+)*\s*(?:ETH|BTC|USD)', header, re.IGNORECASE)
            if amount_match:
                amount = amount_match.group()
            
            # Extract attack vector
            vector_match = re.search(r'(?:Attack Vector|Vulnerability|Root Cause):\s*([^\n]+)', header, re.IGNORECASE)
            if vector_match:
                attack_vector = vector_match.group(1).strip()
            
            # Extract TX hash
            tx_match = re.search(r'(?:TX|Transaction):\s*(0x[a-fA-F0-9]{64})', header)
            if tx_match:
                tx_hash = tx_match.group(1)
            
            # Extract analysis URL
            url_match = re.search(r'https?://[^\s\n]+', header)
            if url_match:
                analysis_url = url_match.group()
        
        # Categorize the exploit
        category = categorize_exploit(content, filepath.name)
        
        # Create description from code comments and structure
        description = create_description(content, protocol, attack_vector)
        
        return Exploit(
            filename=filepath.name,
            filepath=str(filepath),
            protocol=protocol or filepath.stem,
            date=date,
            amount_lost=amount,
            attack_vector=attack_vector,
            description=description,
            code=content,
            category=category,
            tx_hash=tx_hash,
            analysis_url=analysis_url,
        )
        
    except Exception as e:
        console.print(f"[red]Error parsing {filepath}: {e}[/red]")
        return None


def categorize_exploit(content: str, filename: str) -> str:
    """Categorize exploit based on content analysis."""
    content_lower = content.lower()
    filename_lower = filename.lower()
    
    categories = {
        "reentrancy": ["reentrancy", "reentrant", "callback", "onFlashLoan", "receive()", "fallback()"],
        "oracle-manipulation": ["oracle", "price manipulation", "getprice", "twap", "chainlink"],
        "flash-loan": ["flashloan", "flash loan", "onFlashLoan", "executeOperation"],
        "access-control": ["onlyowner", "authorized", "permission", "role", "admin"],
        "governance": ["governance", "vote", "proposal", "delegate"],
        "liquidation": ["liquidate", "liquidation", "collateral"],
        "first-depositor": ["first deposit", "share inflation", "donation"],
        "signature": ["signature", "ecrecover", "replay"],
        "arithmetic": ["overflow", "underflow", "precision"],
        "front-running": ["frontrun", "sandwich", "mev"],
    }
    
    for category, keywords in categories.items():
        for keyword in keywords:
            if keyword in content_lower or keyword in filename_lower:
                return category
    
    return "other"


def create_description(content: str, protocol: str, attack_vector: str) -> str:
    """Create a searchable description from the exploit."""
    # Extract function names
    functions = re.findall(r'function\s+(\w+)', content)
    
    # Extract external calls
    external_calls = re.findall(r'(\w+)\.([\w]+)\(', content)
    
    # Extract key comments
    comments = re.findall(r'//\s*(.+)', content)
    key_comments = [c for c in comments if len(c) > 20 and not c.startswith('SPDX')][:5]
    
    description_parts = [
        f"Protocol: {protocol}",
        f"Attack: {attack_vector}" if attack_vector else "",
        f"Functions: {', '.join(set(functions[:10]))}",
        f"External calls: {', '.join([f'{c[0]}.{c[1]}' for c in external_calls[:10]])}",
        "Key comments: " + "; ".join(key_comments) if key_comments else "",
    ]
    
    return "\n".join([p for p in description_parts if p])


def index_exploits(incremental: bool = False):
    """Index all exploits into ChromaDB."""
    console.print("[bold blue]Indexing DeFiHackLabs exploits...[/bold blue]")
    
    # Find all Solidity files
    poc_dir = DEFIHACKLABS_DIR / "src" / "test"
    if not poc_dir.exists():
        console.print(f"[red]PoC directory not found: {poc_dir}[/red]")
        console.print("[yellow]Run: git clone https://github.com/SunWeb3Sec/DeFiHackLabs.git data/DeFiHackLabs[/yellow]")
        return
    
    sol_files = list(poc_dir.glob("**/*.sol"))
    console.print(f"Found {len(sol_files)} Solidity files")
    
    # Initialize ChromaDB
    CHROMA_DIR.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    
    # Create or get collection
    try:
        if incremental:
            collection = client.get_collection("exploits")
        else:
            # Delete existing and recreate
            try:
                client.delete_collection("exploits")
            except:
                pass
            collection = client.create_collection(
                name="exploits",
                metadata={"description": "DeFiHackLabs exploit PoCs"}
            )
    except:
        collection = client.create_collection(
            name="exploits",
            metadata={"description": "DeFiHackLabs exploit PoCs"}
        )
    
    # Parse and index
    indexed = 0
    with Progress() as progress:
        task = progress.add_task("[cyan]Indexing...", total=len(sol_files))
        
        for filepath in sol_files:
            exploit = parse_exploit_file(filepath)
            
            if exploit:
                # Create document for embedding
                document = f"""
Protocol: {exploit.protocol}
Category: {exploit.category}
Attack Vector: {exploit.attack_vector}
Amount Lost: {exploit.amount_lost}
Date: {exploit.date}

Description:
{exploit.description}

Code Preview:
{exploit.code[:2000]}
"""
                
                # Add to collection
                collection.add(
                    documents=[document],
                    metadatas=[{
                        "filename": exploit.filename,
                        "filepath": exploit.filepath,
                        "protocol": exploit.protocol,
                        "category": exploit.category,
                        "attack_vector": exploit.attack_vector,
                        "amount_lost": exploit.amount_lost,
                        "date": exploit.date,
                        "tx_hash": exploit.tx_hash or "",
                        "analysis_url": exploit.analysis_url or "",
                    }],
                    ids=[exploit.filename]
                )
                indexed += 1
            
            progress.advance(task)
    
    console.print(f"[bold green]Indexed {indexed} exploits![/bold green]")


if __name__ == "__main__":
    import sys
    incremental = "--incremental" in sys.argv
    index_exploits(incremental=incremental)
