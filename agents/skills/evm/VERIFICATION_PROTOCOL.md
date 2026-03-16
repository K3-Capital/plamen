# Verification Protocol

> How to prove a hypothesis is TRUE or FALSE using Foundry tests.

---

## Evidence Source Tracking (MANDATORY)

> **CRITICAL**: For EVERY piece of evidence used in verification, you MUST tag its source. Evidence from mocks or unverified external contracts CANNOT support a REFUTED verdict.

### Evidence Source Tags

| Tag | Meaning | Valid for REFUTED? |
|-----|---------|-------------------|
| [PROD] | Production contract (verified on-chain) | YES |
| [MOCK] | Mock/test contract | **NO** |
| [CODE] | Audited codebase (in-scope) | YES |
| [EXT-UNV] | External, unverified behavior | **NO** |
| [DOC] | Documentation/spec only | NO (needs verification) |

### Evidence Audit Table (REQUIRED in every verification output)

Before ANY verdict, fill this table:

```markdown
### Evidence Audit
| Claim | Evidence Source | Tag | Valid for REFUTED? |
|-------|-----------------|-----|-------------------|
| "External returns X" | Mock contract | [MOCK] | NO |
| "State changes to Y" | Protocol.sol:123 | [CODE] | YES |
| "Transfer triggers Z" | Etherscan source | [PROD] | YES |
```

### Mock Rejection Rule

**AUTOMATIC OVERRIDE**: If ANY evidence supporting REFUTED has tag [MOCK] or [EXT-UNV]:
- CANNOT return REFUTED
- MUST return CONTESTED
- Triggers production verification (Step 4a.5)

**Example**:
```markdown
## Verdict: REFUTED -> CONTESTED (mock evidence override)

### Evidence Audit
| Claim | Source | Tag | Valid? |
|-------|--------|-----|--------|
| "Staking returns shares" | StakingMock.sol:45 | [MOCK] | NO |

**Override reason**: REFUTED verdict relies on mock behavior at StakingMock.sol:45.
Production contract behavior is UNVERIFIED. Must fetch production source.
```

---

## Pre-Verification Understanding

Before writing ANY test code, you MUST answer:

### Question 1: What is the EXACT bug?
```
NOT: "Something is inconsistent"
NOT: "State is wrong"
NOT: "Reentrancy possible"

YES: "[Variable] is [read/written] at [location] but should be [read/written]
      at [other location] because [specific reason]"
```

### Question 2: What OBSERVABLE difference proves it?
```
NOT: "Values are different"
NOT: "State changed"

YES: "Before operation: [variable] = [expected value]
      After operation: [variable] = [actual value]
      Expected: [what it should be]"
```

### Question 3: What is the EXACT assertion?
```
NOT: assertTrue(bugExists)
NOT: assertFalse(isSecure)

YES: assertEq(actualValue, expectedValue, "description of what's wrong")
 OR: assertNotEq(before, after, "value changed when it shouldn't")
 OR: assertGt(error, threshold, "error exceeds acceptable threshold")
```

**If you cannot answer all three -> ASK FOR CLARIFICATION**

---

## Pre-PoC Feasibility Gates (MANDATORY)

Before writing test code, verify these two gates. If either FAILS, adjust the hypothesis.

### Gate F1: Reachability
Trace a call path from a permissionless entry point to the vulnerable code.

- [ ] Entry point identified (public/external/entry function)
- [ ] Call path traced through intermediary functions
- [ ] All access checks on the path are passable by the attacker profile

If NO entry point reaches the vulnerable code → UNREACHABLE → FALSE_POSITIVE.
If reachable only through a restricted path → document the restriction, adjust likelihood.

### Gate F2: Math Bounds
Substitute real-world value domains into the expression that triggers the bug.

- [ ] Parameter domains identified (token decimals, max supply, TVL range, fee range, time bounds)
- [ ] Expression evaluated at worst-case feasible inputs
- [ ] Result crosses the bug threshold

If the bug requires values outside feasible domains → INFEASIBLE → FALSE_POSITIVE.
If feasible only at extreme but realistic parameters → document the threshold, proceed with adjusted severity.

**Both gates PASS → proceed to PoC. Either gate FAILS → document and stop.**

---

## Test File Template

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/**
 * @title Test_H{N}: {Title}
 *
 * BUG: {2 sentence description}
 * EXPECTED: {what should happen}
 * ACTUAL: {what does happen}
 */
contract Test_H{N} is Test {

    // === CONTRACTS ===
    // Declare target contract and any dependencies

    // === ACTORS ===
    address attacker = makeAddr("attacker");
    address victim = makeAddr("victim");
    address owner = makeAddr("owner");

    // === SETUP ===
    function setUp() public {
        // Deploy contracts
        // Set initial state
        // Fund actors if needed
    }

    // === TEST: Direct bug demonstration ===
    function test_H{N}_bug_demonstration() public {
        // 1. RECORD BEFORE
        console.log("=== BEFORE ===");
        uint256 valueBefore = target.criticalValue();
        console.log("Critical value:", valueBefore);

        // 2. ACTION
        console.log("=== ACTION ===");
        // Perform the operation that triggers the bug

        // 3. RECORD AFTER
        console.log("=== AFTER ===");
        uint256 valueAfter = target.criticalValue();
        console.log("Critical value:", valueAfter);

        // 4. PROVE BUG
        console.log("=== VERIFICATION ===");
        // THE ASSERTION THAT PROVES THE BUG
        // Design this so it PASSES when the bug EXISTS
    }

    // === TEST: Impact demonstration (optional) ===
    function test_H{N}_impact() public {
        // Show cumulative impact or attacker profit
    }
}
```

---

## Interpreting Results

### Test PASSES -> Bug CONFIRMED
The assertion that "proves the bug" succeeded.
- If `assertNotEq(after, before)` passes -> values ARE different (bug exists)
- If `assertGt(error, threshold)` passes -> error IS above threshold (bug exists)

### Test FAILS -> Check Why

| Failure | Meaning | Action |
|---------|---------|--------|
| Assertion failed: values equal | Bug doesn't exist as hypothesized | Re-examine hypothesis |
| Revert in setup | Deployment/config wrong | Fix setup |
| Revert in action | Operation blocked | Check preconditions |
| Arithmetic error | Values wrong | Check calculations |

---

## Iteration Protocol

**Attempt 1:** Direct implementation of test strategy from hypothesis

**Attempt 2:** Adjust parameters
- Different amounts (larger/smaller)
- Different timing (more/fewer blocks)
- Different actors

**Attempt 3:** Re-examine assumptions
- Is setup correct?
- Are preconditions met?
- Is the bug mechanism correctly understood?

**After 3 attempts:**
- If still fails -> FALSE_POSITIVE with documented reasoning
- Explain why the hypothesis was wrong

---

## Severity Determination

### CRITICAL
- Direct fund theft possible
- Protocol insolvency
- No special prerequisites needed
- Attacker profits significantly

### HIGH
- Fund loss with some setup
- Broken core functionality
- Significant value at risk
- Cumulative error compounds quickly

### MEDIUM
- Limited fund loss
- Requires specific conditions
- Edge cases with real impact
- Moderate value at risk

### LOW
- Negligible direct impact
- Extreme edge cases only
- Owner/admin controlled risk
- Informational with minor consequence

---

## Output Format

### CONFIRMED

```markdown
## Verdict: CONFIRMED

### Bug Mechanism Verified
{Explain what the test proves in 2-3 sentences}

### Test File
`test/audit/Test_H{N}.t.sol`

### Test Output
```
{Paste relevant forge test output}
```

### Key Evidence
| Metric | Value |
|--------|-------|
| Before | {value} |
| After | {value} |
| Expected | {value} |
| Difference | {calculation} |

### Severity: {LEVEL}
{Justification in 1-2 sentences}
```

### FALSE_POSITIVE

```markdown
## Verdict: FALSE_POSITIVE

### Attempts Made

**Attempt 1:**
- Approach: {description}
- Result: {what happened}
- Learning: {insight}

**Attempt 2:**
- Approach: {description}
- Result: {what happened}
- Learning: {insight}

**Attempt 3:**
- Approach: {description}
- Result: {what happened}
- Learning: {insight}

### Why It's Not a Bug
{Explain the actual behavior and why hypothesis was wrong in 2-3 sentences}
```

### CONTESTED (NEW in v5 -- CRITICAL)

```markdown
## Verdict: CONTESTED

### Evidence Status
| Checkpoint | Status | Details |
|------------|--------|---------|
| External behavior verified against PRODUCTION | NO | Used mock behavior as evidence |
| All callers checked | YES | Checked A, B, C |
| Profit calculated with attacker holding | NO | Only analyzed donation loss |

### Why This Cannot Be REFUTED
{Explain what evidence is missing to definitively rule out the bug}

### Escalation Required
- [ ] Fetch production contract source for {external dep}
- [ ] Re-analyze with attacker holding shares
- [ ] Check additional caller paths: {list}

### Current Assessment
Likely: {TRUE_POSITIVE / FALSE_POSITIVE / UNKNOWN}
Confidence: {LOW / MEDIUM}
```

---

## Insufficient Evidence (HALT CONDITIONS — CRITICAL)

> **MANDATORY**: You MUST check ALL boxes before returning REFUTED.
> If ANY checkbox is NO -> Return CONTESTED, not REFUTED.

Before marking REFUTED, check:
- [ ] External behavior verified against PRODUCTION (not mock)
  - Read `{scratchpad}/external_production_behavior.md`
  - If external dep is marked 'UNVERIFIED' -> CANNOT use as evidence
  - If mock differs from production -> use PRODUCTION behavior
- [ ] Attack path checked on ALL callers (not just main path)
  - Use `mcp__slither-analyzer__get_function_callers()` to enumerate
- [ ] Profit calculated with attacker HOLDING tokens (not just donating)
  - "Attacker loses by donating" is NOT sufficient evidence
  - Check: what if attacker holds X% of shares BEFORE donating?
- [ ] **Missing precondition documented**
  - Document in structured format: precondition type + why it blocks
  - Types: STATE / ACCESS / TIMING / EXTERNAL / BALANCE
- [ ] **Searched other findings for matching postconditions**
  - Read `{scratchpad}/findings_inventory.md` for CONFIRMED/PARTIAL findings
  - Check if ANY finding creates the postcondition that would enable this attack
  - If match found -> CONTESTED, not REFUTED (chain analysis will combine)

### Evidence That Does NOT Count
- "Mock shows X" -- mocks != production (CRITICAL: always verify against production)
- "Standard ERC20" -- may have transfer hooks, side effects
- "Attacker loses by donating" -- may profit via shares held
- "Function is internal" -- may be called by public function
- "Requires admin" -- admin may be compromised or malicious
- "Attacker cannot acquire X" -- another finding may CREATE this condition

### Anti-Downgrade Halt for VS/BLIND Findings (HARD RULE)
For findings from Validation Sweep ([VS-*]) or Blind Spot Scanner ([BLIND-*]): apply Rule 13's 5-question test BEFORE any downgrade.
**HALT**: If test shows users harmed AND unavoidable AND undocumented -> you CANNOT return FALSE_POSITIVE. Minimum verdict: CONTESTED.
Defense parity gaps (Contract A has protection X, Contract B lacks it for same action) are NEVER "by design" -> minimum severity: Medium, minimum verdict: CONTESTED.
Violating this halt is a workflow error equivalent to using [MOCK] evidence for REFUTED.

### Chain Analysis Integration

A finding is NEVER truly REFUTED until chain analysis completes.

If you mark a finding as REFUTED but document a missing precondition, the chain analyzer
(Step 6b) will search for other findings whose postconditions match your missing precondition.
If found, the finding will be escalated to CONTESTED and combined into a chain hypothesis.

**Example**:
- Your finding: "Donation attack blocked because attacker cannot hold receipt tokens"
- Other finding: "External protocol interaction returns transferable receipt tokens"
- Chain: Other finding enables your finding -> Combined HIGH severity

---

## RAG Queries Before PoC (MANDATORY for HIGH/CRITICAL)

Before writing PoC tests for HIGH/CRITICAL findings, query the vulnerability database:

### Step 1: Get Attack Vectors
```
mcp__unified-vuln-db__get_attack_vectors(bug_class="{category}")
```
Returns step-by-step attack strategies from real exploits.

### Step 2: Get PoC Templates
```
mcp__unified-vuln-db__get_poc_template(bug_class="{category}", framework="foundry")
```
Returns example test structures for this vulnerability type.

### Step 3: Get Similar Exploit Code
```
mcp__unified-vuln-db__get_similar_findings(pattern="{vulnerability description}")
```
Returns similar historical findings with code examples.

### Step 4: Validate Before Committing
```
mcp__unified-vuln-db__validate_hypothesis(hypothesis="{your finding summary}")
```
Returns supporting/contradicting evidence from historical exploits.

### RAG Integration Rules

| RAG Result | Impact on Verification |
|------------|----------------------|
| Attack vector found | Use documented steps as test basis |
| PoC template available | Adapt template to this protocol |
| Similar exploit exists | Extract key attack pattern |
| No similar findings | Proceed with manual analysis, note uncertainty |

### Document RAG Evidence

In the verification output, add:

```markdown
### RAG Evidence
- **Attack Vectors Consulted**: [list bug classes queried]
- **Similar Exploits Found**: [count and brief descriptions]
- **PoC Template Used**: [yes/no, which template]
- **Historical Precedent**: [describe any matching historical vulnerabilities]
```

---

## Exchange Rate Finding Severity (MANDATORY)

> **CRITICAL**: Before assigning severity to ANY finding affecting share/asset ratios or exchange rates, you MUST complete this quantitative analysis. Do NOT use qualitative terms without numbers.

### Required Quantitative Analysis

For findings affecting exchange rates, fill in this table:

| Metric | Value | Source |
|--------|-------|--------|
| Protocol TVL | [X ETH or USD] | Production or documented estimate |
| Attack cost | [Y] | Calculated from attack steps (gas, tokens, opportunity) |
| Attacker profit | [Z] | Calculated (extraction - cost) |
| Victim loss per user | [W] | Calculated per affected user |
| Affected user count | [N] | one / some / all |
| Profit ratio | [Z/Y] | Attacker profit / attack cost |

### Severity Calculation

**Step 1**: Calculate total impact = W * N (victim loss * affected users)

**Step 2**: Calculate profitability = Z/Y (attacker profit / cost)

**Step 3**: Apply severity matrix:

| Total Impact | Profitability > 2x | Profitability 1-2x | Profitability < 1x |
|--------------|-------------------|-------------------|-------------------|
| > $100,000 | CRITICAL | HIGH | HIGH |
| $10,000 - $100,000 | HIGH | HIGH | MEDIUM |
| $1,000 - $10,000 | HIGH | MEDIUM | MEDIUM |
| < $1,000 | MEDIUM | LOW | LOW |

### Example Calculation (Donation Attack)

```markdown
| Metric | Value | Source |
|--------|-------|--------|
| Protocol TVL | $100M | Documentation |
| Attack cost | 1000 TOKEN (~$500) | Direct donation amount |
| Attacker profit | 100,000 TOKEN (~$50,000) | Exchange rate * shares held |
| Victim loss per user | Variable | Depends on timing |
| Affected user count | All future depositors | Until reconciliation |
| Profit ratio | 100x | $50,000 / $500 |

**Severity**: HIGH (Total impact > $10k, profitability > 2x)
```

### What NOT to Do

- "This enables MEV-style extraction" (qualitative, no numbers)
- "Attacker can profit significantly" (undefined)
- "Loss of funds possible" (unquantified)
- "Medium severity due to complexity" (no calculation)

### What TO Do

- "Attacker profits 100,000 TOKEN ($50,000) from 1,000 TOKEN ($500) investment"
- "Each victim loses up to 1% of deposit value, affecting all users"
- "Total extractable value: $50,000 with 100x profit ratio -> HIGH"

---

## Design Flaw Severity Escalation

When a finding is classified as a "design flaw" or "accounting inaccuracy" rather than an exploit, apply this escalation check:

| Criterion | YES/NO |
|-----------|--------|
| Risk-free for the attacker (no capital at risk, or attacker profits even if partial) | |
| Repeatable (can be executed on every occurrence of a triggering event) | |
| Scales with protocol usage (impact grows with TVL, user count, or time) | |
| No mitigation without code change (off-chain monitoring cannot prevent, only detect) | |

**If ALL 4 criteria are YES**: Severity floor = MEDIUM (cannot be rated LOW or Informational)
**If 3 of 4 criteria are YES**: Recheck -- the remaining criterion may not actually block the attack at scale

**Rationale**: Design flaws that are risk-free, repeatable, scaling, and unmitigable are effectively permanent value extraction channels. Even if per-event profit is small, cumulative impact over protocol lifetime is significant. "Attacker loses money" is only a valid downgrade if the loss is CERTAIN and PROPORTIONAL -- not if the attacker can structure the trade to break even or profit.

---

## Using RAG for Test Ideas

If stuck on how to write a test:

```
mcp__unified-vuln-db__get_poc_template(
  vulnerability_type="{category from hypothesis}"
)
```

This returns example test structures for common vulnerability types.

---

## Bidirectional Role Analysis (MANDATORY)

> **CRITICAL**: Semi-trusted role findings CANNOT be marked REFUTED unless BOTH directions are analyzed.

### HALT CONDITIONS for Semi-Trusted Role Findings

Before marking ANY finding involving BOT/KEEPER/OPERATOR roles as REFUTED:

- [ ] **Direction 1 analyzed**: ROLE -> USER harm scenarios (Steps 1-4 of SEMI_TRUSTED_ROLES.md)
- [ ] **Direction 2 analyzed**: USER -> ROLE exploitation (Steps 5-6 of SEMI_TRUSTED_ROLES.md)
- [ ] **Precondition Griefability table completed**: All role function preconditions checked
- [ ] **User exploitation scenarios documented**: Scenarios D, E, F from skill

### Direction 2 Enforcement

If Direction 2 (USER -> ROLE) is NOT analyzed:
- CANNOT return REFUTED
- MUST return CONTESTED with note: "Direction 2 not analyzed"
- Finding flagged for depth review

**Example**:
```markdown
## Finding [SR-3]: Keeper timing abuse

**Verdict**: CONTESTED (not REFUTED)
**Reason**: Only Direction 1 (keeper->user) analyzed. Direction 2 (user->keeper) not analyzed.

### Missing Analysis
- [ ] Can users predict keeper timing?
- [ ] Can users manipulate preconditions to block keeper?
- [ ] What is system degradation if keeper is blocked?

**Step Execution**: checkmark1,2,3,4 | x5,6(not analyzed) -> INCOMPLETE
```

---

## RAG Confidence Override

> **PURPOSE**: Prevent dismissal of findings with strong historical precedent.

### RAG Confidence Scoring

When validating a hypothesis, RAG returns a confidence score based on:
- Number of similar findings in database
- Severity distribution of similar findings
- Match quality (exact pattern vs. related pattern)

### Override Rules

| RAG Confidence | Local Verdict | Final Verdict | Action |
|----------------|---------------|---------------|--------|
| >= 7/8 matches | FALSE_POSITIVE | **CONTESTED** (override) | Cannot dismiss -- strong precedent |
| >= 6/8 matches | FALSE_POSITIVE | **CONTESTED** (override) | Cannot dismiss -- significant precedent |
| < 6/8 matches | FALSE_POSITIVE | FALSE_POSITIVE | Allowed -- limited precedent |

**Implementation**:
```markdown
### RAG Confidence Check
- Similar findings found: 8
- HIGH severity matches: 5
- RAG confidence: 8/8 (>=6 threshold)
- **Override applied**: Cannot mark FALSE_POSITIVE

## Verdict: CONTESTED (RAG override)
**Reason**: 8 similar HIGH findings in database. Local analysis suggests FALSE_POSITIVE but historical precedent too strong to dismiss.
```

---

## Chain Hypothesis Protection

> **CRITICAL**: Chain hypotheses receive elevated protection because they represent multi-step attacks that were initially missed.

### Protection Rules

1. **RAG >= 6/8 + Chain**: Cannot be dismissed as FALSE_POSITIVE
2. **3+ agents flagged + Chain**: Need PRODUCTION evidence to refute
3. **Chain PoC MUST test full sequence**: Both enabler AND blocked finding

### Chain PoC Requirements

```solidity
// Chain PoC MUST demonstrate COMPLETE sequence
function test_CH1_full_chain() public {
    // ========================================
    // STEP 1: ENABLER (Finding B)
    // Execute the action that creates postcondition
    // ========================================

    // Record state BEFORE enabler
    uint256 tokensBefore = token.balanceOf(attacker);

    // Execute enabler action
    // ... enabler code ...

    // ========================================
    // VERIFY POSTCONDITION CREATED
    // Assert the precondition for Finding A is now met
    // ========================================

    uint256 tokensAfter = token.balanceOf(attacker);
    assertTrue(tokensAfter > tokensBefore, "Enabler created tokens");

    // ========================================
    // STEP 2: BLOCKED FINDING (Finding A)
    // Execute the attack that was previously blocked
    // ========================================

    // ... blocked attack code using acquired tokens ...

    // ========================================
    // VERIFY CHAIN IMPACT
    // Assert combined impact (should exceed either alone)
    // ========================================

    uint256 profit = /* calculate */;
    assertGt(profit, 0, "Chain attack profitable");
}
```

### Chain Dismissal Requirements

To mark a chain hypothesis as FALSE_POSITIVE, you MUST:
1. Prove enabler finding does NOT create the postcondition, OR
2. Prove blocked finding still blocked EVEN WITH the postcondition, OR
3. Prove chain sequence is impossible due to timing/access/state constraints

Each proof requires [PROD] or [CODE] evidence -- no [MOCK] evidence allowed.

### Bidirectional Chain Analysis (Rule 6 Extension)
For chain hypotheses where enabler OR blocked finding involves a semi-trusted role (BOT/KEEPER/OPERATOR):
Verify BOTH directions: (1) role executes chain to harm users, AND (2) users exploit role's timing/sequencing to trigger chain.
If only one direction analyzed -> verdict CANNOT be FALSE_POSITIVE. Return CONTESTED with note: "Chain bidirectional analysis incomplete."
This extends standalone Rule 6 halt to multi-step chain sequences.

---

## Fork Testing (Preferred for External Dependencies)

When hypothesis involves external contract behavior, **prefer Anvil fork testing** over mocked tests:

1. **Start Anvil fork**: `mcp__foundry-suite__anvil_start(fork_url=RPC_URL)` -- forks mainnet state
2. **Run PoC against forked state**: Real external contracts, real balances, real behavior
3. **Evidence level**: Fork tests provide [PROD-FORK] evidence (valid for REFUTED verdicts)
4. **When to use**: Any hypothesis where external contract behavior is central to the verdict

Fork testing eliminates the need for manual production source fetching in most cases.

## Foundry Suite PoC Methodology

When writing PoC tests, use these MCP tools for realistic verification:

### Local Fork Testing
1. Start local mainnet fork: `mcp__foundry-suite__anvil_start` with fork URL
2. Execute PoC script: `mcp__foundry-suite__forge_script` for realistic execution
3. Inspect state: `mcp__foundry-suite__cast_call` to read contract state
4. Send transactions: `mcp__foundry-suite__cast_send` for state changes
5. Check balances: `mcp__evm-chain-data__get_token_balance` / `get_balance`

### Production Contract Verification
- Read contract state directly: `mcp__evm-chain-data__read_contract(address, network, function_name, args)`
- Get contract ABI: `mcp__evm-chain-data__get_contract_abi(address, network)`
- Check transaction receipts: `mcp__evm-chain-data__get_transaction_receipt`

### Evidence Tagging
Tag all evidence with source type:
- [PROD-ONCHAIN]: From production contract read
- [PROD-SOURCE]: From verified source on block explorer
- [PROD-FORK]: From mainnet fork test
- [CODE]: From audited codebase
- [MOCK]: From mock/test contract -- CANNOT support REFUTED for external behavior
- [EXT-UNV]: External, unverified -- CANNOT support REFUTED for external behavior
