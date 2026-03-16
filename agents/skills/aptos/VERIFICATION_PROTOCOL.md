# Verification Protocol -- Aptos Move

> How to prove a hypothesis is TRUE or FALSE using Move unit tests.

---

## Evidence Source Tracking (MANDATORY)

> **CRITICAL**: For EVERY piece of evidence used in verification, you MUST tag its source. Evidence from mocks or unverified external modules CANNOT support a REFUTED verdict.

### Evidence Source Tags

| Tag | Meaning | Valid for REFUTED? |
|-----|---------|-------------------|
| [PROD-ONCHAIN] | Production module verified on Aptos Explorer | YES |
| [PROD-SOURCE] | Source code verified on-chain (Aptos Explorer source verification) | YES |
| [CODE] | Audited codebase (in-scope) | YES |
| [MOCK] | Mock/test module | **NO** |
| [EXT-UNV] | External module, unverified behavior | **NO** |
| [DOC] | Documentation/spec only | NO (needs verification) |

### Evidence Audit Table (REQUIRED in every verification output)

Before ANY verdict, fill this table:

```markdown
### Evidence Audit
| Claim | Evidence Source | Tag | Valid for REFUTED? |
|-------|-----------------|-----|-------------------|
| "External module returns X" | Mock module | [MOCK] | NO |
| "State changes to Y" | protocol_module.move:123 | [CODE] | YES |
| "Coin transfer triggers Z" | Aptos Explorer source | [PROD-ONCHAIN] | YES |
```

### Mock Rejection Rule

**AUTOMATIC OVERRIDE**: If ANY evidence supporting REFUTED has tag [MOCK] or [EXT-UNV]:
- CANNOT return REFUTED
- MUST return CONTESTED
- Triggers production verification

**Example**:
```markdown
## Verdict: REFUTED -> CONTESTED (mock evidence override)

### Evidence Audit
| Claim | Source | Tag | Valid? |
|-------|--------|-----|--------|
| "Staking returns shares" | test_staking.move:45 | [MOCK] | NO |

**Override reason**: REFUTED verdict relies on mock behavior at test_staking.move:45.
Production module behavior is UNVERIFIED. Must verify against on-chain source.
```

---

## Pre-Verification Understanding

Before writing ANY test code, you MUST answer:

### Question 1: What is the EXACT bug?
```
NOT: "Something is inconsistent"
NOT: "State is wrong"
NOT: "Capability leak possible"

YES: "[Variable/resource] is [read/written/moved] at [location] but should be
      [read/written/moved] at [other location] because [specific reason]"
```

### Question 2: What OBSERVABLE difference proves it?
```
NOT: "Values are different"
NOT: "State changed"

YES: "Before operation: [resource/value] = [expected value]
      After operation: [resource/value] = [actual value]
      Expected: [what it should be]"
```

### Question 3: What is the EXACT assertion?
```
NOT: assert!(bug_exists, 0)
NOT: assert!(!is_secure, 0)

YES: assert!(actual_value == expected_value, ERROR_CODE)
 OR: assert!(before != after, ERROR_CODE)  // "value changed when it shouldn't"
 OR: assert!(error > threshold, ERROR_CODE)  // "error exceeds acceptable threshold"
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

```move
#[test_only]
module test_addr::test_hypothesis_N {
    use std::signer;
    use std::string;
    use aptos_framework::account;
    use aptos_framework::coin;
    use aptos_framework::aptos_coin;
    use aptos_framework::timestamp;
    use aptos_framework::fungible_asset;
    use aptos_framework::object;
    use aptos_framework::primary_fungible_store;

    // Import protocol modules under test
    // use protocol_addr::module_name;

    /// BUG: {2 sentence description}
    /// EXPECTED: {what should happen}
    /// ACTUAL: {what does happen}

    // === CONSTANTS ===
    const INITIAL_BALANCE: u64 = 1_000_000_000; // 10 APT (8 decimals)
    const ATTACK_AMOUNT: u64 = 100_000_000;     // 1 APT

    // === SETUP HELPER ===
    fun setup_test(
        aptos_framework: &signer,
        admin: &signer,
        attacker: &signer,
        victim: &signer,
    ) {
        // Initialize timestamp for time-dependent tests
        timestamp::set_time_has_started_for_testing(aptos_framework);

        // Create test accounts
        account::create_account_for_test(signer::address_of(admin));
        account::create_account_for_test(signer::address_of(attacker));
        account::create_account_for_test(signer::address_of(victim));

        // Initialize and fund with AptosCoin if needed
        // let (burn_cap, mint_cap) = aptos_coin::initialize_for_test(aptos_framework);
        // coin::register<aptos_coin::AptosCoin>(attacker);
        // aptos_coin::mint(aptos_framework, signer::address_of(attacker), INITIAL_BALANCE);

        // Deploy and configure protocol
        // module_name::initialize(admin, ...);
    }

    // === TEST: Direct bug demonstration ===
    #[test(
        aptos_framework = @aptos_framework,
        admin = @protocol_addr,
        attacker = @0x123,
        victim = @0x456
    )]
    fun test_HN_bug_demonstration(
        aptos_framework: &signer,
        admin: &signer,
        attacker: &signer,
        victim: &signer,
    ) {
        setup_test(aptos_framework, admin, attacker, victim);

        // 1. RECORD BEFORE
        // let value_before = module_name::get_critical_value();

        // 2. ACTION -- perform the operation that triggers the bug
        // module_name::vulnerable_function(attacker, ATTACK_AMOUNT);

        // 3. RECORD AFTER
        // let value_after = module_name::get_critical_value();

        // 4. PROVE BUG -- assertion PASSES when bug EXISTS
        // assert!(value_after != value_before, 0); // or specific condition
    }

    // === TEST: Impact demonstration (optional) ===
    #[test(
        aptos_framework = @aptos_framework,
        admin = @protocol_addr,
        attacker = @0x123,
        victim = @0x456
    )]
    fun test_HN_impact(
        aptos_framework: &signer,
        admin: &signer,
        attacker: &signer,
        victim: &signer,
    ) {
        setup_test(aptos_framework, admin, attacker, victim);

        // Show cumulative impact or attacker profit
        // Multiple iterations of exploit if repeatable
    }

    // === TEST: Expected revert (if testing access control) ===
    #[test(
        aptos_framework = @aptos_framework,
        admin = @protocol_addr,
        attacker = @0x123
    )]
    #[expected_failure(abort_code = 0x50003, location = protocol_addr::module_name)]
    fun test_HN_should_revert_but_doesnt(
        aptos_framework: &signer,
        admin: &signer,
        attacker: &signer,
    ) {
        // If this test FAILS (does NOT abort), the access control is broken
        // setup...
        // module_name::admin_only_function(attacker); // should abort but doesn't
    }
}
```

### Move Test Patterns

**Time manipulation**:
```move
// Advance time by N seconds
timestamp::fast_forward_seconds(3600); // 1 hour
```

**Account creation**:
```move
account::create_account_for_test(signer::address_of(user));
```

**Coin setup (legacy Coin standard)**:
```move
let (burn_cap, mint_cap) = aptos_coin::initialize_for_test(aptos_framework);
coin::register<AptosCoin>(user);
aptos_coin::mint(aptos_framework, user_addr, amount);
```

**Fungible Asset setup (new FA standard)**:
```move
// FA objects are typically created in module init
// For testing, use the module's initialization function
```

**Object creation for testing**:
```move
let constructor_ref = object::create_object(signer::address_of(admin));
let object_signer = object::generate_signer(&constructor_ref);
```

**Expected failure annotation**:
```move
#[expected_failure]                                    // any abort
#[expected_failure(abort_code = 1)]                    // specific code
#[expected_failure(abort_code = 0x10001, location = module_addr::module)] // category + reason
```

---

## Interpreting Results

### Test PASSES -> Bug CONFIRMED
The assertion that "proves the bug" succeeded.
- If `assert!(after != before, 0)` passes -> values ARE different (bug exists)
- If `assert!(error > threshold, 0)` passes -> error IS above threshold (bug exists)

### Test FAILS -> Check Why

| Failure | Meaning | Action |
|---------|---------|--------|
| Assertion failed (abort code) | Bug doesn't exist as hypothesized | Re-examine hypothesis |
| Abort in setup | Module initialization wrong | Fix setup (check init order, missing resources) |
| Abort in action | Operation blocked (access control, precondition) | Check preconditions, signer requirements |
| ARITHMETIC_ERROR (0x20001) | Overflow/underflow or division by zero | Check calculations, validate inputs |
| RESOURCE_NOT_FOUND | Missing `move_to` in setup | Ensure all required resources are initialized |
| ALREADY_EXISTS | Duplicate resource creation | Check init called only once |

### Common Aptos-Specific Test Issues

| Issue | Cause | Fix |
|-------|-------|-----|
| `ENOT_FOUND` on coin operations | Account not registered for coin type | Add `coin::register<CoinType>(user)` before operations |
| Timestamp not available | `timestamp` module not initialized | Add `timestamp::set_time_has_started_for_testing(aptos_framework)` |
| Object not found | Object created at unexpected address | Use `object::create_named_object` with deterministic seed |
| Module not published | Test module can't import protocol module | Check `Move.toml` dependencies and test address mapping |
| Signer mismatch | `@protocol_addr` doesn't match expected | Verify `#[test(...)]` signer addresses match module publish address |

---

## Iteration Protocol

**Attempt 1:** Direct implementation of test strategy from hypothesis

**Attempt 2:** Adjust parameters
- Different amounts (larger/smaller, boundary values)
- Different timing (advance more/fewer seconds)
- Different actors (swap attacker/victim roles)
- Different resource initialization order

**Attempt 3:** Re-examine assumptions
- Is setup correct? (all resources initialized, correct init order)
- Are preconditions met? (correct signer, sufficient balance, required state)
- Is the bug mechanism correctly understood?
- Are module dependencies correctly configured in Move.toml?

**After 3 attempts:**
- If still fails -> FALSE_POSITIVE with documented reasoning
- Explain why the hypothesis was wrong

---

## Severity Determination

### CRITICAL
- Direct fund theft possible (drain FungibleStore, mint unlimited tokens)
- Protocol insolvency (assets < liabilities)
- No special prerequisites needed (permissionless exploit)
- Attacker profits significantly
- Ref capability leak granting unrestricted mint/transfer/burn

### HIGH
- Fund loss with some setup (specific state required)
- Broken core functionality (deposits, withdrawals, swaps non-functional)
- Significant value at risk
- Cumulative error compounds quickly
- Ref capability leak with limited but significant blast radius

### MEDIUM
- Limited fund loss (bounded by rate limits, caps)
- Requires specific conditions (timing, state, multi-step)
- Edge cases with real impact
- Moderate value at risk
- Access control weakness that requires compromised friend module

### LOW
- Negligible direct impact
- Extreme edge cases only
- Admin/owner controlled risk with compensating controls
- Informational with minor consequence

---

## Output Format

### CONFIRMED

```markdown
## Verdict: CONFIRMED

### Evidence Audit
| Claim | Evidence Source | Tag | Valid for REFUTED? |
|-------|-----------------|-----|-------------------|

### Bug Mechanism Verified
{Explain what the test proves in 2-3 sentences}

### Test File
`tests/audit/test_hypothesis_N.move`

### Test Output
```
{Paste relevant `aptos move test` output}
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

### RAG Evidence
- **Attack Vectors Consulted**: [list bug classes queried]
- **Similar Exploits Found**: [count and brief descriptions]
- **PoC Template Used**: [yes/no, which template]
- **Historical Precedent**: [describe any matching historical vulnerabilities]
```

### FALSE_POSITIVE

```markdown
## Verdict: FALSE_POSITIVE

### Evidence Audit
| Claim | Evidence Source | Tag | Valid for REFUTED? |
|-------|-----------------|-----|-------------------|

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

### CONTESTED (CRITICAL)

```markdown
## Verdict: CONTESTED

### Evidence Audit
| Claim | Evidence Source | Tag | Valid for REFUTED? |
|-------|-----------------|-----|-------------------|

### Evidence Status
| Checkpoint | Status | Details |
|------------|--------|---------|
| External behavior verified against PRODUCTION | NO | Used mock behavior as evidence |
| All callers checked | YES | Checked A, B, C |
| Ref access paths fully traced | NO | Friend module re-export not analyzed |
| Profit calculated with attacker holding | NO | Only analyzed donation loss |

### Why This Cannot Be REFUTED
{Explain what evidence is missing to definitively rule out the bug}

### Escalation Required
- [ ] Fetch production module source from Aptos Explorer for {external dep}
- [ ] Re-analyze with attacker holding shares/tokens
- [ ] Check additional caller paths: {list}
- [ ] Trace Ref access through friend modules: {list}

### Current Assessment
Likely: {TRUE_POSITIVE / FALSE_POSITIVE / UNKNOWN}
Confidence: {LOW / MEDIUM}
```

---

## Insufficient Evidence (HALT CONDITIONS) -- CRITICAL

> **MANDATORY**: You MUST check ALL boxes before returning REFUTED.
> If ANY checkbox is NO -> Return CONTESTED, not REFUTED.

Before marking REFUTED, check:
- [ ] External behavior verified against PRODUCTION (not mock)
  - Check Aptos Explorer for on-chain module source verification
  - If external module is marked 'UNVERIFIED' -> CANNOT use as evidence
  - If mock differs from production -> use PRODUCTION behavior
- [ ] Attack path checked on ALL callers (not just main path)
  - Enumerate all `public fun` and `public entry fun` that reach the vulnerable code
  - Check `public(friend) fun` callers via friend module analysis
- [ ] Ref capability paths fully traced
  - For Ref-related findings: trace every path from Ref creation to Ref usage
  - Check friend modules for transitive Ref access
  - Check if ExtendRef-derived signer enables unexpected access
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
- "Standard Coin module" -- may have custom transfer hooks via fungible_asset dispatch
- "Attacker loses by donating" -- may profit via shares held
- "Function is private/friend" -- friend module may expose it publicly
- "Requires admin signer" -- admin may be compromised or malicious
- "Attacker cannot acquire X" -- another finding may CREATE this condition
- "Ref is in private storage" -- friend module may provide access path

### Anti-Downgrade Halt for VS/BLIND Findings (HARD RULE)
For findings from Validation Sweep ([VS-*]) or Blind Spot Scanner ([BLIND-*]): apply Rule 13's 5-question test BEFORE any downgrade.
**HALT**: If test shows users harmed AND unavoidable AND undocumented -> you CANNOT return FALSE_POSITIVE. Minimum verdict: CONTESTED.
Defense parity gaps (Module A has protection X, Module B lacks it for same action) are NEVER "by design" -> minimum severity: Medium, minimum verdict: CONTESTED.
Violating this halt is a workflow error equivalent to using [MOCK] evidence for REFUTED.

### Chain Analysis Integration

A finding is NEVER truly REFUTED until chain analysis completes.

If you mark a finding as REFUTED but document a missing precondition, the chain analyzer
will search for other findings whose postconditions match your missing precondition.
If found, the finding will be escalated to CONTESTED and combined into a chain hypothesis.

**Example**:
- Your finding: "Drain attack blocked because attacker cannot get TransferRef"
- Other finding: "Friend module exposes TransferRef via public function"
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
mcp__unified-vuln-db__get_poc_template(bug_class="{category}", framework="move_test")
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
| Protocol TVL | [X APT or USD] | Production or documented estimate |
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

### What NOT to Do

- "This enables MEV-style extraction" (qualitative, no numbers)
- "Attacker can profit significantly" (undefined)
- "Loss of funds possible" (unquantified)
- "Medium severity due to complexity" (no calculation)

### What TO Do

- "Attacker profits 100,000 APT ($50,000) from 1,000 APT ($500) investment"
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

**Step Execution**: check1,2,3,4 | x5,6(not analyzed) -> INCOMPLETE
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

```move
#[test(
    aptos_framework = @aptos_framework,
    admin = @protocol_addr,
    attacker = @0x123,
    victim = @0x456
)]
fun test_CH1_full_chain(
    aptos_framework: &signer,
    admin: &signer,
    attacker: &signer,
    victim: &signer,
) {
    // setup...

    // ========================================
    // STEP 1: ENABLER (Finding B)
    // Execute the action that creates postcondition
    // ========================================

    // Record state BEFORE enabler
    // let balance_before = coin::balance<CoinType>(signer::address_of(attacker));

    // Execute enabler action
    // ... enabler code ...

    // ========================================
    // VERIFY POSTCONDITION CREATED
    // Assert the precondition for Finding A is now met
    // ========================================

    // let balance_after = coin::balance<CoinType>(signer::address_of(attacker));
    // assert!(balance_after > balance_before, 0); // "Enabler created tokens"

    // ========================================
    // STEP 2: BLOCKED FINDING (Finding A)
    // Execute the attack that was previously blocked
    // ========================================

    // ... blocked attack code using acquired tokens/capabilities ...

    // ========================================
    // VERIFY CHAIN IMPACT
    // Assert combined impact (should exceed either alone)
    // ========================================

    // let profit = ...;
    // assert!(profit > 0, 0); // "Chain attack profitable"
}
```

### Chain Dismissal Requirements

To mark a chain hypothesis as FALSE_POSITIVE, you MUST:
1. Prove enabler finding does NOT create the postcondition, OR
2. Prove blocked finding still blocked EVEN WITH the postcondition, OR
3. Prove chain sequence is impossible due to timing/access/state constraints

Each proof requires [PROD-ONCHAIN], [PROD-SOURCE], or [CODE] evidence -- no [MOCK] evidence allowed.

### Bidirectional Chain Analysis (Rule 6 Extension)
For chain hypotheses where enabler OR blocked finding involves a semi-trusted role (BOT/KEEPER/OPERATOR):
Verify BOTH directions: (1) role executes chain to harm users, AND (2) users exploit role's timing/sequencing to trigger chain.
If only one direction analyzed -> verdict CANNOT be FALSE_POSITIVE. Return CONTESTED with note: "Chain bidirectional analysis incomplete."
This extends standalone Rule 6 halt to multi-step chain sequences.

---

## Aptos-Specific Verification Considerations

### No Fork Testing Equivalent
Aptos does not have an equivalent to Ethereum's Anvil/Hardhat fork testing. All tests run in the Move test framework's local VM.

**Compensation**:
- For external module behavior: verify source on Aptos Explorer using [PROD-ONCHAIN] tag, then replicate behavior in test mocks (document the production behavior being replicated)
- For on-chain state verification: use `aptos move view` or Aptos REST API to query production state, tag as [PROD-ONCHAIN]
- When mock replication is unavoidable: clearly tag as [MOCK] and note which production behavior it replicates

### Module Publish Address Matters
In Move, module identity is tied to the publish address. Ensure test signers match expected addresses:
```move
#[test(admin = @protocol_addr)]  // admin IS the module publisher
```
If the protocol uses `@protocol_addr` as a privileged address, the test signer MUST match.

### Resource Initialization Order
Move resources must be initialized in dependency order. Common initialization sequence:
1. `timestamp::set_time_has_started_for_testing(aptos_framework)`
2. `account::create_account_for_test(addr)` for each account
3. Coin type registration: `coin::register<CoinType>(signer)`
4. Protocol initialization: `protocol::initialize(admin, ...)`
5. State setup: create pools, mint initial tokens, set parameters

### Ability Constraints
Move's type system enforces abilities (`copy`, `drop`, `store`, `key`). Tests cannot:
- Copy a resource without `copy` ability (e.g., cannot duplicate a Ref)
- Drop a resource without `drop` ability (must be explicitly moved/destructured)
- Store a resource in global storage without `key` ability

If a test fails due to ability constraints, this is EVIDENCE of the Move type system preventing the attack -- document it as a mitigation, not a test failure.

### Generics and Phantom Types
When testing generic modules (e.g., `Pool<CoinA, CoinB>`), ensure type parameters are correctly instantiated. Phantom type parameters (`phantom CoinType`) must still exist as registered types.

---

## Production Verification for Aptos

### On-Chain Module Source
- Aptos Explorer: `https://explorer.aptoslabs.com/account/{address}/modules`
- REST API: `https://fullnode.mainnet.aptoslabs.com/v1/accounts/{address}/modules`
- Tag: [PROD-SOURCE]

### On-Chain State
- View functions: `aptos move view --function-id {address}::{module}::{function}`
- REST API resources: `https://fullnode.mainnet.aptoslabs.com/v1/accounts/{address}/resources`
- Tag: [PROD-ONCHAIN]

### On-Chain Events
- REST API events: `https://fullnode.mainnet.aptoslabs.com/v1/accounts/{address}/events/{event_handle}/{field_name}`
- Tag: [PROD-ONCHAIN]

---

## Using RAG for Test Ideas

If stuck on how to write a test:

```
mcp__unified-vuln-db__get_poc_template(
  vulnerability_type="{category from hypothesis}"
)
```

This returns example test structures for common vulnerability types. Adapt Solidity PoC patterns to Move test syntax where applicable.
