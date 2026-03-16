# Phase 4b: Invariant Fuzz Generator (v9.9.5)

> **Purpose**: LLM-generated Foundry invariant tests targeting semantic invariants and depth findings.
> **Model**: sonnet (mechanical generation task — translates invariants into Solidity test code)
> **Budget**: 0 depth slots (runs between semantic invariants and depth agents; cost = 1 sonnet agent + forge execution)
> **Trigger**: Always runs when `semantic_invariants.md` exists AND `foundry.toml` exists in project root.
> **Skip**: If project uses Hardhat only (no `foundry.toml`) → skip entirely. Hardhat has no native invariant test support.
> **Time cap**: 5-minute timeout enforced via shell. Campaign uses `--invariant-runs 64 --invariant-depth 15 --fail-on-revert false`.

---

## Generator Agent Template

```
Task(subagent_type="general-purpose", model="sonnet", prompt="
You are the Invariant Fuzz Generator. You translate semantic invariants into Foundry invariant tests, run them, and report any violations as findings.

## Your Inputs
Read:
- {SCRATCHPAD}/semantic_invariants.md (Main Table — semantic invariants for each state variable)
- {SCRATCHPAD}/state_variables.md (variable types, contracts)
- {SCRATCHPAD}/function_list.md (public/external functions — these become handler targets)
- {SCRATCHPAD}/contract_inventory.md (contract paths)
- Source files referenced in semantic_invariants.md

## STEP 1: Select Invariants (max 8)

From semantic_invariants.md, pick up to 8 invariants prioritized by:
1. Variables flagged with SYNC_GAP, ACCUMULATION_EXPOSURE, or CONDITIONAL (highest priority)
2. Variables in clusters with Partial-Write Functions (medium priority)
3. Core accounting invariants (totalAssets >= totalShares, fee accumulator monotonicity)

For each selected invariant, write a 1-line Solidity assertion:
| Variable | Invariant (English) | Assertion (Solidity) |

## STEP 2: Generate Handler Contract

Write a Foundry test file to {PROJECT_ROOT}/test/invariant/InvariantFuzz.t.sol:

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import \"forge-std/Test.sol\";
// Import target contracts based on contract_inventory.md

contract Handler is Test {
    // Target contract instances (initialized in setUp)

    // For each public/external state-mutating function on target contracts:
    // function handler_functionName(bounded params) external {
    //     // Bound params to realistic ranges using bound()
    //     // Call target function inside try/catch (do not revert on expected failures)
    // }
}

contract InvariantFuzz is Test {
    Handler handler;
    // Target contract instances

    function setUp() public {
        // Deploy target contracts with minimal valid configuration
        // Deploy handler with target references
        // targetContract(address(handler));
        // targetSelector — include all handler functions
    }

    // For each selected invariant:
    // function invariant_variableName() public view {
    //     // Assert the semantic invariant
    // }
}
```

**Handler rules**:
- Bound all uint params: `amount = bound(amount, 0, 1e24)` (realistic range, not type max)
- Use `try/catch` for external calls — handler must not revert
- Include `warp(bound(dt, 0, 365 days))` handlers for time-dependent invariants
- Include `deal()` for token balance setup where needed
- Max 15 handler functions (prioritize state-mutating functions from function_list.md)

## STEP 3: Compile and Run Campaign

First compile:
```bash
cd {PROJECT_ROOT} && forge build 2>&1 | tail -20
```

If compilation fails: read error, fix imports/types, retry ONCE. If still fails: report compilation error, skip execution, and return early.

Then run with enforced timeout (5 minutes max):
```bash
cd {PROJECT_ROOT} && timeout 300 forge test --match-contract InvariantFuzz --invariant-runs 64 --invariant-depth 15 --fail-on-revert false -vv 2>&1 | head -200
```

On Windows, use:
```bash
cd {PROJECT_ROOT} && forge test --match-contract InvariantFuzz --invariant-runs 64 --invariant-depth 15 --fail-on-revert false -vv 2>&1 | head -200
```
(Foundry's internal timeout handles runaway campaigns; the 64-run cap limits wall time)

## STEP 4: Report Results

Write to {SCRATCHPAD}/invariant_fuzz_results.md:

```markdown
# Invariant Fuzz Results

## Campaign Summary
- Invariants tested: {N}
- Runs: {runs}
- Violations found: {V}
- Compilation: SUCCESS/FAILED (reason)

## Invariant Results
| Invariant | Status | Counterexample (if violated) | Related Finding |
|-----------|--------|-----------------------------:|----------------|

## Violations (Findings)
For each violation, use standard finding format with [FUZZ-N] IDs:
- Include the counterexample call sequence from forge output
- Map to existing semantic invariant flags where applicable
- Severity: use standard matrix (invariant violations on core accounting = High likelihood)
```

If NO violations found: write summary with 'No violations detected in {runs} runs' and return.
Violations become depth agent input — they provide concrete counterexamples for investigation.

Return: 'DONE: {N} invariants tested, {V} violations found'
")
```
