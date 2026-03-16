# Unified Vulnerability Database

A single ChromaDB-based RAG system that aggregates vulnerabilities from multiple sources.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Unified Vulnerability DB                  │
│                        (ChromaDB)                            │
├─────────────────────────────────────────────────────────────┤
│  Collection: "vulnerabilities"                               │
│  - Semantic search across ALL sources                        │
│  - Metadata filtering by source/severity/category            │
│  - Local embeddings (no data exfiltration)                   │
└─────────────────────────────────────────────────────────────┘
                              ▲
                              │ Unified Schema
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
   ┌────┴────┐          ┌────┴────┐          ┌────┴────┐
   │ Solodit │          │DeFiHack │          │HuggingF │
   │ Scraper │          │  Labs   │          │ Dataset │
   └─────────┘          └─────────┘          └─────────┘
   (8000+ findings)     (500+ PoCs)          (10K+ samples)
```

## Unified Schema

All vulnerabilities are normalized to this schema:

```python
{
    # Identification
    "id": "source-unique-id",
    "source": "solodit|defihacklabs|huggingface|code4rena|sherlock",
    
    # Classification
    "category": "reentrancy|oracle|flash-loan|access-control|...",
    "severity": "critical|high|medium|low|info",
    "protocol_type": "dex|lending|vault|bridge|staking|governance|nft|token",
    
    # Content
    "title": "Short descriptive title",
    "description": "Full description of the vulnerability",
    "impact": "What damage can occur",
    "root_cause": "Why the vulnerability exists",
    "attack_vector": "How to exploit",
    
    # Code
    "code_snippet": "Vulnerable code excerpt",
    "has_poc": true|false,
    "poc_code": "Full PoC if available",
    
    # Metadata
    "protocol_name": "Affected protocol name",
    "audit_firm": "Auditor who found it",
    "date": "YYYY-MM-DD",
    "url": "Source URL",
    "recommendation": "How to fix",
    
    # Tags
    "tags": ["tag1", "tag2"],
}
```

## Data Sources

### 1. Solodit (scraped)
- 8000+ audit findings from major security firms
- Categories: reentrancy, oracle, access-control, etc.
- Severities: Critical, High, Medium, Low, Info

### 2. DeFiHackLabs (cloned repo)
- 500+ real exploit PoCs with working code
- Actual attack transactions
- Loss amounts and dates

### 3. HuggingFace Dataset (downloaded)
- darkknight25/Smart_Contract_Vulnerability_Dataset
- 10K+ vulnerability samples
- Labeled by vulnerability type

### 4. Future Sources
- Code4rena contest findings
- Sherlock contest findings
- Immunefi bug bounty reports

## Key Features

### Local Embeddings
Uses `sentence-transformers` to avoid sending vulnerability data to external APIs:
```python
from sentence_transformers import SentenceTransformer
model = SentenceTransformer('all-MiniLM-L6-v2')  # Runs locally
```

### Smart Chunking
Different chunk strategies for different content types:
- **Description**: Full semantic chunks
- **Code**: Function-level chunks with context
- **Metadata**: Stored separately for filtering

### Hybrid Search
Combines semantic search with metadata filtering:
```python
collection.query(
    query_texts=["reentrancy with external call"],
    where={"severity": {"$in": ["critical", "high"]}},
    where_document={"$contains": "callback"},
    n_results=10
)
```

## Installation

```bash
cd custom-mcp/unified-vuln-db
pip install -r requirements.txt

# Index all sources
python -m unified_vuln.indexer --all

# Or index specific sources
python -m unified_vuln.indexer --source solodit
python -m unified_vuln.indexer --source defihacklabs
python -m unified_vuln.indexer --source huggingface
```

## MCP Tools

| Tool | Description |
|------|-------------|
| `search_vulnerabilities` | Semantic search across all sources |
| `search_by_category` | Filter by vulnerability category |
| `search_by_severity` | Filter by severity level |
| `get_similar_exploits` | Find similar vulnerabilities to code snippet |
| `get_poc_code` | Get full PoC code for a finding |
| `get_statistics` | Database statistics by source/category |

## Query Examples

```python
# Find reentrancy in vaults
search_vulnerabilities(
    query="reentrancy vulnerability in ERC4626 vault",
    categories=["reentrancy"],
    protocol_types=["vault"],
    min_severity="medium"
)

# Find similar to code snippet
get_similar_exploits(
    code="function withdraw() external { msg.sender.call{value: balance}(''); balance = 0; }",
    top_k=5
)

# Get all flash loan exploits with PoC
search_vulnerabilities(
    query="flash loan price manipulation",
    has_poc=True,
    sources=["defihacklabs"]
)
```

## Maintenance

```bash
# Update all sources
python -m unified_vuln.updater --all

# Update specific source
python -m unified_vuln.updater --source defihacklabs

# Rebuild index (full reindex)
python -m unified_vuln.indexer --rebuild
```
