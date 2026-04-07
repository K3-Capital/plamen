import json
import os

config_path = os.path.expanduser("~/.claude.json")

with open(config_path, "r") as f:
    config = json.load(f)

servers = config["mcpServers"]

mcp = os.path.expanduser("~/.claude/mcp-packages").replace("/", "\\")
san = os.path.join(mcp, "schema-sanitizer.js")
nm = os.path.join(mcp, "node_modules")
foundry = os.path.expanduser("~/.foundry/bin").replace("/", "\\")
nodejs = r"C:\Program Files\nodejs"

# Save existing env blocks
envs = {}
for k, v in servers.items():
    if "env" in v:
        envs[k] = v["env"]

# evm-chain-data: PINNED 2.0.4 + SCHEMA SANITIZER
evm_entry = os.path.join(nm, "@mcpdotdirect", "evm-mcp-server", "build", "index.js")
servers["evm-chain-data"] = {
    "command": "cmd",
    "args": ["/c", f"set PATH={foundry};{nodejs};%PATH% && node \"{san}\" node \"{evm_entry}\""]
}

# foundry-suite: PINNED 0.1.5 + SCHEMA SANITIZER
foundry_entry = os.path.join(nm, "@pranesh.asp", "foundry-mcp-server", "dist", "index.js")
servers["foundry-suite"] = {
    "command": "cmd",
    "args": ["/c", f"set PATH={foundry};{nodejs};%PATH% && node \"{san}\" node \"{foundry_entry}\""]
}

# tavily-search: PINNED 0.2.18 (direct node, no npx)
tavily_entry = os.path.join(nm, "tavily-mcp", "build", "index.js")
servers["tavily-search"] = {
    "command": "cmd",
    "args": ["/c", f"set PATH={nodejs};%PATH% && node \"{tavily_entry}\""]
}

# memory: PINNED 2026.1.26 (direct node, no npx)
memory_entry = os.path.join(nm, "@modelcontextprotocol", "server-memory", "dist", "index.js")
servers["memory"] = {
    "command": "cmd",
    "args": ["/c", f"set PATH={nodejs};%PATH% && node \"{memory_entry}\""]
}

# helius: PINNED 0.1.6 (direct node, no npx)
helius_entry = os.path.join(nm, "@mcp-dockmaster", "mcp-server-helius", "dist", "index.js")
servers["helius"] = {
    "command": "cmd",
    "args": ["/c", f"set PATH={nodejs};%PATH% && node \"{helius_entry}\""]
}

# Restore env blocks
for k, env in envs.items():
    if k in servers:
        servers[k]["env"] = env

with open(config_path, "w") as f:
    json.dump(config, f, indent=2)

print("DONE: 5 npm-based MCP servers updated:")
print(f"  evm-chain-data: PINNED 2.0.4 + SANITIZER via {san}")
print(f"  foundry-suite:  PINNED 0.1.5 + SANITIZER")
print(f"  tavily-search:  PINNED 0.2.18 (direct node)")
print(f"  memory:         PINNED 2026.1.26 (direct node)")
print(f"  helius:         PINNED 0.1.6 (direct node)")
print()
print("Unchanged Python servers: unified-vuln-db, slither-analyzer, solana-fender, farofino")
print()
print("To update pinned versions later:")
print(f"  1. Edit {os.path.join(mcp, 'package.json')}")
print(f"  2. Run: cd {mcp} && npm install")
print(f"  3. Restart Claude Code")
