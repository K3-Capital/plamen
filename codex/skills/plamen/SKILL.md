---
name: plamen
description: "Launch Plamen Web3 security audit pipeline"
---

# Plamen Security Audit Pipeline (Codex Orchestrator)

## Usage

```
/plamen [light|core|thorough] [path/to/project]
```

When invoked, follow this orchestration sequence.

## Step 0: Parse Arguments

Parse `$ARGUMENTS`:
- If it contains "light", "core", or "thorough", set `MODE` accordingly (default: core).
- If it contains a path, set `PROJECT_ROOT` to that path. Otherwise use cwd.
- If it contains `docs:` followed by a path, set `DOCS_PATH`.
- If it contains `scope:` followed by a path, set `SCOPE_FILE`.
- If it contains `notes:` followed by text, set `SCOPE_NOTES`.

## Step 0.5: Interactive Setup (when no arguments given)

If MODE was not specified in arguments:

1. Display: "Plamen Web3 Security Auditor -- Codex Runtime"
2. Ask the user: "Which audit mode? [light/core/thorough] (default: core)"
3. Wait for response. Set MODE accordingly. If empty or unrecognized, default to core.
4. Confirm: "Starting {MODE} audit on {PROJECT_ROOT}"

If a path was not specified, use cwd and confirm:
"Target: {cwd} -- correct? [y/n]"
If the user answers "n", ask for the correct path before proceeding.

## Step 1: Language Detection

Detect the project's smart contract language by scanning `PROJECT_ROOT`:

| Detection | Language |
|-----------|----------|
| `foundry.toml` or `.sol` files | `evm` |
| `Anchor.toml` or `programs/` with `.rs` | `solana` |
| `Move.toml` with `[addresses]` + `aptos` deps | `aptos` |
| `Move.toml` with `sui` deps | `sui` |
| `Cargo.toml` with `soroban-sdk` | `soroban` |

Set `LANGUAGE` to the detected value. This resolves all `{LANGUAGE}` placeholders
in file paths throughout the pipeline.

## Step 2: Create Scratchpad

```bash
mkdir -p {PROJECT_ROOT}/.scratchpad
```

Set `SCRATCHPAD = {PROJECT_ROOT}/.scratchpad`.

## Step 3: Initialize Watchdog

```bash
python3 ~/.codex/plamen/hooks/phase_gate.py --init {SCRATCHPAD} {MODE} {PROJECT_ROOT}
```

## Step 4: Execute Phase Sequence

Read `~/.codex/plamen/hooks/phase_manifest.json` for the phase ordering and
artifact requirements. Execute phases in order, checking gates between phases.

### Phase 1: Reconnaissance (4-Agent Split)

Do NOT spawn a single monolithic recon agent. Split into 4 parallel agents
for timeout isolation (confirmed failure on large projects with single agent).

Read the full recon prompt structure from:
`~/.codex/plamen/prompts/{LANGUAGE}/phase1-recon-prompt.md`

**Agent 1A: RAG Meta-Buffer** (FIRE-AND-FORGET)
- Tasks: TASK 0 steps 1-5 (vuln-db probe + Solodit queries)
- Model: defined in agent role TOML (lightweight model -- mechanical query+format task)
- Spawn with `spawn_agent` and do NOT wait for completion
- Writes: `meta_buffer.md`
- If still running after Agents 1B/2/3 finish, abandon it and write:
  `meta_buffer.md` with `## RAG: UNAVAILABLE - agent timed out`

**Agent 1B: Docs + External + Fork** (foreground)
- Tasks: TASK 0 step 6 (fork ancestry), TASK 3 (docs), TASK 11 (external)
- Model: defined in agent role TOML (global model -- web search + design reasoning)
- Role: `~/.codex/agents/recon.toml` (with task subset)
- Writes: `design_context.md`, `external_production_behavior.md`

**Agent 2: Build + Static + Tests** (foreground)
- Tasks: TASK 1 (build), TASK 2 (static analysis), TASK 8 (tests), TASK 9 (coverage)
- Model: defined in agent role TOML (lightweight model -- tool execution + output formatting)
- Role: `~/.codex/agents/recon.toml` (with task subset)
- Writes: `build_status.md`, `function_list.md`, `call_graph.md`,
  `state_variables.md`, `modifiers.md`, `event_definitions.md`,
  `external_interfaces.md`, `static_analysis.md`, `test_results.md`

**Agent 3: Patterns + Surface + Templates** (foreground)
- Tasks: TASK 4 (patterns), TASK 5 (inventory), TASK 6 (surface), TASK 7 (flags),
  TASK 10 (templates)
- Model: defined in agent role TOML (global model -- attack surface + template selection requires reasoning)
- Role: `~/.codex/agents/recon.toml` (with task subset)
- Writes: `contract_inventory.md`, `attack_surface.md`, `detected_patterns.md`,
  `setter_list.md`, `emit_list.md`, `constraint_variables.md`,
  `template_recommendations.md`

### Recon Timeout Policy
Wait maximum 5 minutes for each foreground recon agent.
If an agent hasn't returned after 5 minutes:
1. Check if its assigned artifacts exist in the scratchpad
2. If YES: the agent wrote output but didn't return cleanly. Close it and proceed.
3. If NO: mark those artifacts as MISSING and continue. Note gaps in recon_summary.md.

Agent 1A (RAG) is fire-and-forget. Do NOT wait for it. If meta_buffer.md doesn't exist after other agents finish, write a minimal one: "# Meta-Buffer\n## RAG: UNAVAILABLE"

Wait for Agents 1B, 2, 3 to complete (subject to 5-minute timeout above). Check Agent 1A status:
- If complete: read its `meta_buffer.md` output
- If still running: write empty `meta_buffer.md` and proceed
Then write `recon_summary.md` (orchestrator, not an agent).
Verify all required artifacts exist per phase_manifest.json.

### Phase Gate: Recon -> Breadth
Before spawning breadth agents, verify these artifacts exist and are non-empty:
```powershell
$required = @("design_context.md","attack_surface.md","build_status.md","function_list.md","state_variables.md","contract_inventory.md","template_recommendations.md","detected_patterns.md","setter_list.md","emit_list.md","recon_summary.md")
$missing = $required | Where-Object { -not (Test-Path ".scratchpad\$_") -or (Get-Item ".scratchpad\$_").Length -lt 100 }
if ($missing) { Write-Host "BLOCKED: Missing recon artifacts: $($missing -join ', ')" }
```
If ANY are missing: do NOT proceed. Re-spawn the failed recon agent(s) for the missing artifacts only.

### Phase 3: Breadth Analysis

Read `{SCRATCHPAD}/template_recommendations.md` for agent count and scope split.
Spawn breadth agents in batches of max 6 (from `~/.codex/agents/breadth.toml`):
- Each agent gets a unique `{N}` and scope assignment
- If 7+ agents needed: spawn agents 1-6, wait for all to complete, then spawn 7+
- Wait for all batches to complete
- Verify at least 3 `analysis_*.md` files exist

### Phase Gate: Breadth -> Inventory
Before spawning the inventory agent, verify breadth output exists:
```powershell
$analysisFiles = Get-ChildItem ".scratchpad" -Filter "analysis_*.md" -ErrorAction SilentlyContinue
if ($analysisFiles.Count -lt 3) { Write-Host "BLOCKED: Only $($analysisFiles.Count) analysis_*.md files found (need >= 3)" }
```
If fewer than 3 analysis files exist: do NOT proceed. Re-spawn failed breadth agents.

### Phase 4a: Findings Inventory

Spawn the `inventory` agent (from `~/.codex/agents/inventory.toml`):
- Reads all `analysis_*.md` files
- Produces `findings_inventory.md`

### Phase Gate: Inventory -> Depth
Before proceeding to depth (or re-scan/per-contract), verify inventory exists:
```powershell
if (-not (Test-Path ".scratchpad\findings_inventory.md") -or (Get-Item ".scratchpad\findings_inventory.md").Length -lt 100) {
    Write-Host "BLOCKED: findings_inventory.md missing or empty"
}
```
If findings_inventory.md is missing: do NOT proceed. Re-spawn the inventory agent.

### Phase 3b/3c: Re-Scan and Per-Contract (Thorough only)

If MODE is thorough:
- Read `~/.codex/plamen/rules/phase3b-rescan-prompt.md` for re-scan methodology
- Spawn 2-3 `rescan` agents (from `~/.codex/agents/rescan.toml`) with exclusion list
- Then spawn `per-contract` agents (from `~/.codex/agents/per-contract.toml`),
  one per contract cluster
- Merge new findings into inventory

### Phase 4a.5: Semantic Invariants (Core/Thorough)

If MODE is core or thorough:
- Spawn `semantic-invariant` agent (from `~/.codex/agents/semantic-invariant.toml`)
- Produces `semantic_invariants.md`

### Phase 4b: Depth Loop

Spawn in 2 batches to respect the 8-thread limit:

**Batch 1** (4 agents): Spawn depth agents from their respective TOML roles:
- `depth-token-flow.toml`
- `depth-state-trace.toml`
- `depth-edge-case.toml`
- `depth-external.toml`
Wait for all 4 to complete.

**Batch 2** (up to 6 agents): Spawn scanners + niche agents:
- Scanner agents from `scanner.toml`
- For Core/Thorough: flag-triggered niche agents from `niche-agent.toml`
Wait for all to complete.

For Thorough mode:
- Run confidence scoring via `scoring.toml` agent
- Run iterations 2-3 with DA (Devil's Advocate) role
- Run RAG sweep via `rag-sweep.toml` agent
Read `~/.codex/plamen/rules/phase4-confidence-scoring.md` for the full process.

### Phase Gate: Depth -> Chain
Before spawning chain analysis agents, verify depth output exists:
```powershell
$depthFiles = Get-ChildItem ".scratchpad" -Filter "depth_*_findings.md" -ErrorAction SilentlyContinue
if ($depthFiles.Count -lt 2) { Write-Host "BLOCKED: Only $($depthFiles.Count) depth_*_findings.md files found (need >= 2)" }
```
If fewer than 2 depth findings files exist: do NOT proceed. Re-spawn failed depth agents.

### Phase 4c: Chain Analysis

Spawn `chain-analyzer` agents sequentially:
1. Agent 1: Enabler enumeration + grouping
2. Agent 2: Chain matching + composition coverage

Read `~/.codex/plamen/rules/phase4c-chain-prompt.md` for prompts.

### Phase Gate: Chain -> Verification
Before spawning verifier agents, verify chain analysis output exists:
```powershell
$chainRequired = @("hypotheses.md","chain_hypotheses.md","synthesis_full.md")
$chainMissing = $chainRequired | Where-Object { -not (Test-Path ".scratchpad\$_") -or (Get-Item ".scratchpad\$_").Length -lt 50 }
if ($chainMissing) { Write-Host "BLOCKED: Missing chain artifacts: $($chainMissing -join ', ')" }
```
If ANY chain artifacts are missing: do NOT proceed. Re-spawn the failed chain agent(s).

### Phase 5: Verification

Spawn `verifier` agents in batches of 6 for each hypothesis batch:
- Read `~/.codex/plamen/rules/phase5-poc-execution.md` for PoC rules
- Batch hypotheses by severity (Critical first)
- If more than 6 hypotheses: spawn verifiers 1-6, wait, then spawn 7+
- Execute PoCs and record verdicts

### Phase Gate: Verification -> Report
Before spawning report agents, verify at least one verification file exists:
```powershell
$verifyFiles = Get-ChildItem ".scratchpad" -Filter "verify_*.md" -ErrorAction SilentlyContinue
if ($verifyFiles.Count -lt 1) { Write-Host "BLOCKED: No verify_*.md files found (need >= 1)" }
```
If no verification files exist: do NOT proceed. Re-spawn verifier agents for the highest-severity hypotheses.

### Phase 6: Report Generation

Spawn report agents sequentially per `~/.codex/plamen/rules/phase6-report-prompts.md`:
1. `report-index.toml` agent (1 agent -- assigns clean report IDs, tier assignments). Wait for completion.
2. Three parallel `report-tier-writer.toml` agents (Critical+High, Medium, Low+Info). Wait for all 3.
3. `report-assembler.toml` agent (1 agent -- combines into AUDIT_REPORT.md). Wait for completion.

## Artifact Gate Enforcement

Between each phase, verify required artifacts exist:

```bash
python3 ~/.codex/plamen/hooks/phase_gate.py --stop
```

If artifacts are missing, the gate will block. Complete the current phase
before proceeding.

## Mode Support Status

Not all Claude pipeline features have full Codex parity yet. This table
shows what is supported, what is experimental, and what is not yet implemented.

| Phase | Light | Core | Thorough | Notes |
|-------|-------|------|----------|-------|
| Recon (4-agent split) | Supported | Supported | Supported | |
| Breadth | Supported | Supported | Supported | |
| Inventory | Supported | Supported | Supported | |
| Re-scan (3b) | N/A | N/A | Experimental | Convergence not validated on Codex |
| Per-contract (3c) | N/A | N/A | Experimental | Clustering logic untested |
| Semantic Invariants | N/A | Supported | Supported | |
| Depth Loop iter 1 | Supported | Supported | Supported | |
| Depth Loop iter 2-3 | N/A | N/A | Experimental | DA role + anti-dilution untested |
| Niche Agents | N/A | Supported | Supported | |
| Confidence Scoring | N/A | Supported | Experimental | 4-axis scoring untested |
| RAG Sweep | N/A | Supported | Supported | Fallback chain may differ |
| Chain Analysis | Supported | Supported | Supported | |
| Verification + PoC | Supported | Supported | Experimental | No fuzz variant support |
| Skeptic-Judge | N/A | N/A | Not implemented | Requires Claude pipeline feature |
| Invariant Fuzz | N/A | N/A | Not implemented | Foundry-specific, needs adaptation |
| Medusa Fuzz | N/A | N/A | Not implemented | Parallel campaign, needs adaptation |
| Design Stress Test | N/A | N/A | Experimental | 1 agent slot, untested |
| Finding Perturbation | N/A | N/A | Not implemented | |
| Report (multi-agent) | Supported | Supported | Supported | |

## Mode-Specific Behavior

| Step | Light | Core | Thorough |
|------|-------|------|----------|
| Re-scan (3b/3c) | Skip | Skip | Full |
| Semantic invariants | Skip | Yes | Yes |
| Depth iterations | 1 | 1 | Up to 3 |
| Confidence scoring | Skip | 2-axis | 4-axis |
| Niche agents | Skip | Flag-triggered | Flag-triggered |
| RAG sweep | Skip | 1 agent | 1 agent |
| Verification scope | Chains + Medium+ | Chains + Medium+ | ALL severities |

## MANDATORY FINAL STEP: Report Generation

Regardless of how prior phases ran, you MUST generate the final report.

1. Check: does `{PROJECT_ROOT}/AUDIT_REPORT.md` exist?
2. If NO: spawn report agents (index -> tier writers -> assembler)
3. If still NO after report agents: write a minimal report yourself from the scratchpad artifacts
4. VERIFY: `{PROJECT_ROOT}/AUDIT_REPORT.md` exists and is > 500 bytes

```powershell
if (-not (Test-Path "{PROJECT_ROOT}\AUDIT_REPORT.md") -or (Get-Item "{PROJECT_ROOT}\AUDIT_REPORT.md").Length -lt 500) {
    Write-Host "CRITICAL: AUDIT_REPORT.md missing or incomplete. Generating fallback report."
    # Assemble a minimal report from scratchpad findings
}
```

The audit is NOT complete until AUDIT_REPORT.md exists in the project root.
This is the FINAL assertion before returning to the user.
