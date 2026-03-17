# Automated Setup — Paste This Into Claude Code

> **For users who prefer Claude Code to handle the entire installation.**
> Copy everything below the line into a Claude Code session and it will set up Plamen for you.

---

Please set up Plamen (Web3 Security Auditor) on my machine. Follow these steps exactly:

## Step 1: Clone the repository

```bash
git clone https://github.com/PlamenTSV/plamen.git ~/.claude
cd ~/.claude
git submodule update --init --recursive
```

If `~/.claude` already exists, back it up first:
```bash
mv ~/.claude ~/.claude.backup
```

## Step 2: Install Python dependencies

```bash
pip install -r ~/.claude/requirements.txt
pip install -r ~/.claude/custom-mcp/unified-vuln-db/requirements.txt
pip install -r ~/.claude/custom-mcp/solodit-scraper/requirements.txt
pip install -r ~/.claude/custom-mcp/defihacklabs-rag/requirements.txt
pip install -e ~/.claude/custom-mcp/solana-fender
pip install -r ~/.claude/custom-mcp/farofino-mcp/requirements.txt
pip install -e ~/.claude/custom-mcp/slither-mcp  # EVM only — skip if not auditing Solidity
```

## Step 3: Configure MCP servers

Copy the example config and tell me which API keys you have:
```bash
cp ~/.claude/mcp.json.example ~/.claude/mcp.json
```

Then edit `~/.claude/mcp.json`:
- Replace `YOUR_RPC_URL` with an Ethereum RPC URL (Alchemy/Infura free tier, or public: `https://eth.llamarpc.com`)
- Replace `YOUR_ETHERSCAN_API_KEY` with a free key from https://etherscan.io/apis (optional)
- Replace `YOUR_TAVILY_API_KEY` with a free key from https://tavily.com (optional)
- Replace `YOUR_HELIUS_API_KEY` with a free key from https://helius.dev (optional, Solana only)
- Update the `command` paths for Python and slither-mcp to match my system

For the Python command path, run `which python` (Unix) or `where python` (Windows) and use that path.

## Step 4: Configure permissions

```bash
cp ~/.claude/settings.json.example ~/.claude/settings.json
```

## Step 5: Build the RAG vulnerability database

```bash
cd ~/.claude/custom-mcp/unified-vuln-db
python -m unified_vuln.indexer index -s solodit --max-pages 10
python -m unified_vuln.indexer index -s defihacklabs
python -m unified_vuln.indexer index -s immunefi
python -m unified_vuln.indexer stats
```

## Step 6: Verify installation

Run the terminal wrapper to check everything:
```bash
python ~/.claude/plamen.py setup
```

This shows the toolchain status box. If any optional tools are missing (Foundry, Solana CLI, etc.), the Setup menu can install them automatically.

## Step 7: Add to PATH (optional)

So I can just type `plamen` from any directory:

**Unix/macOS** — add to shell profile:
```bash
echo 'export PATH="$HOME/.claude:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

**Windows** — run in PowerShell:
```powershell
[System.Environment]::SetEnvironmentVariable("Path", "$env:USERPROFILE\.claude;" + [System.Environment]::GetEnvironmentVariable("Path", "User"), "User")
```

## Done

After setup, I can start an audit by typing `plamen` in my terminal or `/plamen` inside Claude Code.
