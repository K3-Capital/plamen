# Verification Protocol (Sui Move)

> **Trigger Pattern**: Always (used by all verifier agents)
> **Inject Into**: security-verifier agents (Phase 5)
> **Purpose**: Prove hypotheses TRUE or FALSE using Sui Move test framework with `test_scenario` PoC code.

---

## Evidence Source Tracking (MANDATORY)

> **CRITICAL**: For EVERY piece of evidence used in verification, you MUST tag its source.
> Evidence from mocks or unverified external packages CANNOT support a REFUTED verdict.

### Evidence Source Tags

| Tag | Meaning | Valid for REFUTED? |
|-----|---------|-------------------|
| [PROD-ONCHAIN] | Production Sui object data (via Sui Explorer or RPC) | YES |
| [PROD-SOURCE] | Verified source from Sui Explorer / published package | YES |
| [PROD-PUBLISHED] | Test against published package bytecode | YES |
| [CODE] | Audited codebase (in-scope source) | YES |
| [MOCK] | Mock/test modules or objects | **NO** |
| [EXT-UNV] | External, unverified package behavior | **NO** |
| [DOC] | Documentation/spec only | **NO** (needs verification) |

### Evidence Audit Table (REQUIRED in every verification output)

Before ANY verdict, fill this table:

```markdown
### Evidence Audit
| Claim | Evidence Source | Tag | Valid for REFUTED? |
|-------|-----------------|-----|-------------------|
| "External package returns X" | Mock module | [MOCK] | NO |
| "Object ownership is Y" | sources/module.move:123 | [CODE] | YES |
| "Shared object state is Z" | Sui Explorer object view | [PROD-ONCHAIN] | YES |
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
| "External module validates input" | test_helper.move:45 | [MOCK] | NO |

**Override reason**: REFUTED verdict relies on mock behavior at test_helper.move:45.
Production package behavior is UNVERIFIED. Must fetch published package source.
```

---

## Pre-Verification Understanding

Before writing ANY test code, you MUST answer:

### Question 1: What is the EXACT bug?
```
NOT: "Object ownership is wrong"
NOT: "Access control is missing"
NOT: "State is inconsistent"

YES: "Function [X] in module [Y] accepts shared object [Z] as `&mut` without
      verifying caller holds [CapabilityType], allowing any address to mutate
      field [W] at line [N]"
```

### Question 2: What OBSERVABLE difference proves it?
```
NOT: "State changed"
NOT: "Object was modified"

YES: "Before exploit: pool.total_supply = 1000, attacker_balance = 0
      After exploit: pool.total_supply = 1000, attacker_balance = 500
      Expected: transaction should have aborted with ENotAuthorized"
```

### Question 3: What is the EXACT assertion?
```
NOT: assert!(exploit_worked, 0)

YES: assert!(coin::value(&stolen_coin) > 0, ERR_EXPLOIT_FAILED)
 OR: // Transaction should abort -- if it succeeds, the bug exists
 OR: assert!(state_after.field != state_before.field, ERR_STATE_UNCHANGED)
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

## Test File Templates

### Template 1: Basic Exploit (Shared Object Mutation Without Authorization)

```move
#[test_only]
module exploit::test_shared_object_mutation {
    use sui::test_scenario;
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;

    // Import the target module
    use target_package::target_module;

    /// BUG: {2-sentence description}
    /// EXPECTED: {what should happen}
    /// ACTUAL: {what does happen}
    #[test]
    fun test_unauthorized_shared_object_mutation() {
        let admin = @0xAD;
        let attacker = @0xAA;

        // === SETUP: Deploy protocol and create shared objects ===
        let mut scenario = test_scenario::begin(admin);
        {
            // Initialize protocol -- creates shared config, pools, etc.
            target_module::initialize(test_scenario::ctx(&mut scenario));
        };

        // === RECORD BEFORE STATE ===
        test_scenario::next_tx(&mut scenario, attacker);
        {
            let pool = test_scenario::take_shared<target_module::Pool>(&scenario);
            let value_before = target_module::get_balance(&pool);
            // Log or store value_before for comparison
            std::debug::print(&value_before);
            test_scenario::return_shared(pool);
        };

        // === EXECUTE EXPLOIT ===
        test_scenario::next_tx(&mut scenario, attacker);
        {
            let mut pool = test_scenario::take_shared<target_module::Pool>(&scenario);
            // Attacker calls function on shared object WITHOUT holding required capability
            // If bug exists: this succeeds (no auth check)
            // If bug fixed: this aborts with auth error
            target_module::vulnerable_function(
                &mut pool,
                /* malicious args */
                test_scenario::ctx(&mut scenario),
            );
            test_scenario::return_shared(pool);
        };

        // === VERIFY IMPACT ===
        test_scenario::next_tx(&mut scenario, attacker);
        {
            let pool = test_scenario::take_shared<target_module::Pool>(&scenario);
            let value_after = target_module::get_balance(&pool);
            // THE ASSERTION THAT PROVES THE BUG
            // Design this so it PASSES when the bug EXISTS
            assert!(value_after != value_before, 0);
            test_scenario::return_shared(pool);
        };

        test_scenario::end(scenario);
    }
}
```

### Template 2: Capability Object Theft/Misuse

Tests whether capability objects with `store` ability can be transferred and misused.

```move
#[test_only]
module exploit::test_capability_theft {
    use sui::test_scenario;
    use sui::transfer;

    use target_package::target_module::{Self, AdminCap};

    #[test]
    fun test_admin_cap_transfer_and_misuse() {
        let admin = @0xAD;
        let attacker = @0xAA;

        // === SETUP: Create protocol with admin capability ===
        let mut scenario = test_scenario::begin(admin);
        {
            target_module::initialize(test_scenario::ctx(&mut scenario));
        };

        // === ADMIN TRANSFERS CAP (simulating social engineering or compromised key) ===
        // This tests whether the protocol allows cap transfer at all (store ability)
        test_scenario::next_tx(&mut scenario, admin);
        {
            let admin_cap = test_scenario::take_from_sender<AdminCap>(&scenario);
            // If AdminCap has `store`, this succeeds via public_transfer
            // If AdminCap lacks `store`, only module-defined transfer works
            transfer::public_transfer(admin_cap, attacker);
        };

        // === ATTACKER USES STOLEN CAP ===
        test_scenario::next_tx(&mut scenario, attacker);
        {
            let admin_cap = test_scenario::take_from_sender<AdminCap>(&scenario);
            let mut pool = test_scenario::take_shared<target_module::Pool>(&scenario);

            // Attacker performs admin action with stolen cap
            target_module::admin_withdraw(
                &admin_cap,
                &mut pool,
                /* drain all funds */
                test_scenario::ctx(&mut scenario),
            );

            test_scenario::return_to_sender(&scenario, admin_cap);
            test_scenario::return_shared(pool);
        };

        // === VERIFY: Attacker received funds ===
        test_scenario::next_tx(&mut scenario, attacker);
        {
            let coin = test_scenario::take_from_sender<Coin<SUI>>(&scenario);
            assert!(coin::value(&coin) > 0, 0);
            test_scenario::return_to_sender(&scenario, coin);
        };

        test_scenario::end(scenario);
    }
}
```

### Template 3: Dynamic Field Manipulation

Tests unauthorized dynamic field addition or missing cleanup.

```move
#[test_only]
module exploit::test_dynamic_field_attack {
    use sui::test_scenario;
    use sui::dynamic_field;

    use target_package::target_module;

    #[test]
    fun test_dynamic_field_pollution() {
        let admin = @0xAD;
        let attacker = @0xAA;

        let mut scenario = test_scenario::begin(admin);
        {
            target_module::initialize(test_scenario::ctx(&mut scenario));
        };

        // === ATTACKER ADDS UNAUTHORIZED DYNAMIC FIELD ===
        test_scenario::next_tx(&mut scenario, attacker);
        {
            let mut shared_obj = test_scenario::take_shared<target_module::SharedState>(&scenario);
            // If access control is missing, attacker can add dynamic fields
            // to shared object, potentially corrupting namespace
            target_module::add_field(
                &mut shared_obj,
                b"malicious_key",
                /* malicious value */
                test_scenario::ctx(&mut scenario),
            );
            test_scenario::return_shared(shared_obj);
        };

        // === VERIFY: Dynamic field exists and corrupts protocol logic ===
        test_scenario::next_tx(&mut scenario, admin);
        {
            let shared_obj = test_scenario::take_shared<target_module::SharedState>(&scenario);
            // Check that the malicious field exists and affects behavior
            let malicious_value = dynamic_field::borrow<vector<u8>, u64>(
                target_module::uid(&shared_obj),
                b"malicious_key",
            );
            assert!(*malicious_value > 0, 0);
            test_scenario::return_shared(shared_obj);
        };

        test_scenario::end(scenario);
    }
}
```

### Template 4: Object Wrapping Value Loss

Tests whether destroying a wrapper object loses the wrapped value.

```move
#[test_only]
module exploit::test_wrapping_value_loss {
    use sui::test_scenario;
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;

    use target_package::target_module;

    #[test]
    fun test_wrapped_balance_lost_on_destroy() {
        let user = @0xBB;

        let mut scenario = test_scenario::begin(user);
        {
            target_module::initialize(test_scenario::ctx(&mut scenario));
        };

        // === USER DEPOSITS (balance gets wrapped inside protocol object) ===
        test_scenario::next_tx(&mut scenario, user);
        {
            let coin = coin::mint_for_testing<SUI>(1000, test_scenario::ctx(&mut scenario));
            let mut protocol_obj = test_scenario::take_shared<target_module::Vault>(&scenario);
            target_module::deposit(
                &mut protocol_obj,
                coin,
                test_scenario::ctx(&mut scenario),
            );
            test_scenario::return_shared(protocol_obj);
        };

        // === TRIGGER DESTRUCTION PATH (if exists) ===
        test_scenario::next_tx(&mut scenario, user);
        {
            let mut protocol_obj = test_scenario::take_shared<target_module::Vault>(&scenario);
            // Call function that destroys/unwraps without returning inner balance
            // If bug exists: balance is silently dropped (if drop ability) or tx aborts
            // If safe: balance is returned to user or error prevents destruction
            target_module::close_vault(
                &mut protocol_obj,
                test_scenario::ctx(&mut scenario),
            );
            test_scenario::return_shared(protocol_obj);
        };

        // === VERIFY: User's funds are not lost ===
        test_scenario::next_tx(&mut scenario, user);
        {
            // If funds were properly returned, user should have a Coin
            // If funds were lost, this take_from_sender will fail
            let coin = test_scenario::take_from_sender<Coin<SUI>>(&scenario);
            assert!(coin::value(&coin) == 1000, 0);
            test_scenario::return_to_sender(&scenario, coin);
        };

        test_scenario::end(scenario);
    }
}
```

### Template 5: Programmable Transaction Block (PTB) Multi-Command Exploit

Tests atomic multi-step attacks within a single transaction. In Sui, PTBs allow composing multiple Move calls atomically.

```move
#[test_only]
module exploit::test_ptb_exploit {
    use sui::test_scenario;
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;

    use target_package::target_module;

    /// Simulates a PTB that chains multiple calls atomically.
    /// In test_scenario, each block within next_tx represents a single tx.
    /// To simulate PTB-like atomicity, chain operations within a single block.
    #[test]
    fun test_atomic_multi_step_exploit() {
        let attacker = @0xAA;

        let mut scenario = test_scenario::begin(attacker);
        {
            target_module::initialize(test_scenario::ctx(&mut scenario));
        };

        // === RECORD BEFORE STATE ===
        test_scenario::next_tx(&mut scenario, attacker);
        let balance_before = {
            let pool = test_scenario::take_shared<target_module::Pool>(&scenario);
            let val = target_module::get_total_value(&pool);
            test_scenario::return_shared(pool);
            val
        };

        // === EXECUTE PTB-LIKE ATOMIC EXPLOIT ===
        // All operations in a single next_tx block are atomic
        test_scenario::next_tx(&mut scenario, attacker);
        {
            let mut pool = test_scenario::take_shared<target_module::Pool>(&scenario);

            // Step 1: Manipulate state (e.g., flash borrow)
            let borrowed = target_module::flash_borrow(
                &mut pool,
                1_000_000,
                test_scenario::ctx(&mut scenario),
            );

            // Step 2: Use borrowed funds to manipulate price/state
            target_module::swap_to_manipulate(
                &mut pool,
                &borrowed,
                test_scenario::ctx(&mut scenario),
            );

            // Step 3: Extract value at manipulated price
            let profit = target_module::extract_at_manipulated_price(
                &mut pool,
                test_scenario::ctx(&mut scenario),
            );

            // Step 4: Repay flash loan
            target_module::flash_repay(
                &mut pool,
                borrowed,
                test_scenario::ctx(&mut scenario),
            );

            test_scenario::return_shared(pool);

            // Transfer profit to attacker
            transfer::public_transfer(profit, attacker);
        };

        // === VERIFY PROFIT ===
        test_scenario::next_tx(&mut scenario, attacker);
        {
            let profit_coin = test_scenario::take_from_sender<Coin<SUI>>(&scenario);
            assert!(coin::value(&profit_coin) > 0, 0);
            test_scenario::return_to_sender(&scenario, profit_coin);

            let pool = test_scenario::take_shared<target_module::Pool>(&scenario);
            let balance_after = target_module::get_total_value(&pool);
            assert!(balance_after < balance_before, 0); // Pool lost funds
            test_scenario::return_shared(pool);
        };

        test_scenario::end(scenario);
    }
}
```

### Template 6: Concurrent Shared Object Access (Ordering Attack)

Tests whether protocol behavior depends on transaction ordering for shared objects.

```move
#[test_only]
module exploit::test_ordering_attack {
    use sui::test_scenario;

    use target_package::target_module;

    #[test]
    fun test_front_run_shared_object() {
        let admin = @0xAD;
        let user = @0xBB;
        let attacker = @0xAA;

        let mut scenario = test_scenario::begin(admin);
        {
            target_module::initialize(test_scenario::ctx(&mut scenario));
        };

        // === SCENARIO A: Normal ordering (admin sets fee, then user trades) ===
        test_scenario::next_tx(&mut scenario, admin);
        {
            let mut config = test_scenario::take_shared<target_module::Config>(&scenario);
            target_module::set_fee(&mut config, 100, test_scenario::ctx(&mut scenario)); // 1%
            test_scenario::return_shared(config);
        };

        test_scenario::next_tx(&mut scenario, user);
        {
            let mut pool = test_scenario::take_shared<target_module::Pool>(&scenario);
            let config = test_scenario::take_shared<target_module::Config>(&scenario);
            let result_normal = target_module::swap(
                &mut pool, &config, /* ... */
                test_scenario::ctx(&mut scenario),
            );
            // Record normal result
            test_scenario::return_shared(pool);
            test_scenario::return_shared(config);
        };

        // === SCENARIO B: Attacker front-runs (attacker acts before admin's fee change) ===
        // Simulate by reversing order: attacker trades BEFORE admin updates fee
        // If protocol reads fee from shared config at execution time,
        // attacker can front-run a fee increase
        test_scenario::next_tx(&mut scenario, attacker);
        {
            let mut pool = test_scenario::take_shared<target_module::Pool>(&scenario);
            let config = test_scenario::take_shared<target_module::Config>(&scenario);
            let result_frontrun = target_module::swap(
                &mut pool, &config, /* same params */
                test_scenario::ctx(&mut scenario),
            );
            // Compare: attacker got better rate than user due to ordering
            test_scenario::return_shared(pool);
            test_scenario::return_shared(config);
        };

        test_scenario::end(scenario);
    }
}
```

---

## Interpreting Results

### Test PASSES -> Bug CONFIRMED
The assertion that "proves the bug" succeeded.

### Test FAILS -> Check Why

| Failure | Meaning | Action |
|---------|---------|--------|
| Abort with error code | Function validation rejected the action | Check if rejection IS the bug or a fix |
| `test_scenario::take_from_sender` fails | Object not at expected address | Check transfer logic in setup |
| `test_scenario::take_shared` fails | Shared object not published | Check initialization creates shared objects |
| Type mismatch | Wrong object type taken from scenario | Fix type parameters |
| Arithmetic abort (overflow/underflow) | Math operation failed | Check if this IS the bug or setup error |
| Borrow checker error (compile) | Cannot borrow object mutably | Restructure test to respect Move borrow rules |

---

## Iteration Protocol

**Attempt 1:** Direct implementation of test strategy from hypothesis.

**Attempt 2:** Adjust parameters:
- Different coin amounts (larger/smaller, edge values like 0, 1, u64::MAX)
- Different transaction ordering (swap next_tx blocks)
- Different actor addresses
- Different object states (empty pool, full pool, single-user, multi-user)

**Attempt 3:** Re-examine assumptions:
- Are shared objects properly published in setup?
- Are capability objects at the right addresses?
- Is the module's initialization complete (all shared objects created)?
- Are type parameters correct (generic type instantiation)?
- Does the function require a `Clock` or `TxContext` argument not provided?

**After 3 attempts:** If still fails -> FALSE_POSITIVE with documented reasoning.

---

## Severity Determination

### CRITICAL
- Direct fund theft (Coin drain from shared pools)
- Unauthorized admin capability acquisition
- Arbitrary package upgrade (if upgrade cap compromised and no timelock)
- No special prerequisites needed
- Attacker profits significantly

### HIGH
- Fund loss with specific setup (object pre-creation, ordering dependency)
- Broken core functionality (deposits, withdrawals, swaps, liquidations)
- Shared object state corruption affecting all users
- Significant TVL at risk

### MEDIUM
- Limited fund loss under specific conditions
- Object state corruption (non-fund data)
- Edge cases with real impact at design limits
- Dynamic field pollution affecting protocol behavior
- Moderate value at risk

### LOW
- Negligible direct impact
- Extreme edge cases only
- Admin-controlled risk (with multisig governance)
- View function / event emission issues
- Stranded non-value objects

---

## Exchange Rate Finding Severity (MANDATORY)

> **CRITICAL**: Before assigning severity to ANY finding affecting share/asset ratios or exchange rates, you MUST complete this quantitative analysis.

### Required Quantitative Analysis

For findings affecting exchange rates, fill in this table:

| Metric | Value | Source |
|--------|-------|--------|
| Protocol TVL | [X SUI or USD] | Production or documented estimate |
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
- "This enables extraction" (qualitative, no numbers)
- "Attacker can profit significantly" (undefined)
- "Loss of funds possible" (unquantified)

### What TO Do
- "Attacker profits 500,000 SUI ($500,000) from 1,000 SUI ($1,000) investment"
- "Each victim loses up to 2% of deposit value, affecting all pool users"
- "Total extractable value: $500,000 with 500x profit ratio -> CRITICAL"

---

## Design Flaw Severity Escalation

When a finding is classified as a "design flaw" rather than an exploit, apply this escalation check:

| Criterion | YES/NO |
|-----------|--------|
| Risk-free for the attacker (no capital at risk, or attacker profits even if partial) | |
| Repeatable (can be executed on every occurrence of a triggering event) | |
| Scales with protocol usage (impact grows with TVL, user count, or time) | |
| No mitigation without code change (off-chain monitoring cannot prevent, only detect) | |

**If ALL 4 criteria are YES**: Severity floor = MEDIUM (cannot be rated LOW or Informational)
**If 3 of 4 criteria are YES**: Recheck -- the remaining criterion may not actually block the attack at scale

---

## RAG Queries Before PoC (MANDATORY for HIGH/CRITICAL)

Before writing PoC tests for HIGH/CRITICAL findings:

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

### Step 5: Live Search for Sui-Specific Precedents
```
mcp__unified-vuln-db__search_solodit_live(
  keywords="{sui move vulnerability pattern}",
  impact=["HIGH", "CRITICAL"],
  tags=["Access Control", "Logic Error"],
  language="Move",
  quality_score=3,
  max_results=15
)
```

### RAG Integration Rules

| RAG Result | Impact on Verification |
|------------|----------------------|
| Attack vector found | Use documented steps as test basis |
| Similar exploit exists | Extract key attack pattern |
| PoC template available | Adapt template to Sui test_scenario |
| No similar findings | Proceed with manual analysis, note uncertainty |

### Document RAG Evidence

In the verification output, add:
```markdown
### RAG Evidence
- **Attack Vectors Consulted**: [list bug classes queried]
- **Similar Exploits Found**: [count and brief descriptions]
- **PoC Template Used**: [yes/no, which template]
- **Historical Precedent**: [describe any matching Sui/Move vulnerabilities]
```

---

## RAG Confidence Override

| RAG Confidence | Local Verdict | Final Verdict | Action |
|----------------|---------------|---------------|--------|
| >= 7/8 matches | FALSE_POSITIVE | **CONTESTED** (override) | Cannot dismiss -- strong precedent |
| >= 6/8 matches | FALSE_POSITIVE | **CONTESTED** (override) | Cannot dismiss -- significant precedent |
| < 6/8 matches | FALSE_POSITIVE | FALSE_POSITIVE | Allowed -- limited precedent |

---

## Chain Hypothesis PoC Requirements

Chain hypotheses receive PRIORITY verification. Multi-step exploits must test the COMPLETE sequence:

```move
#[test]
fun test_chain_hypothesis_full() {
    let admin = @0xAD;
    let attacker = @0xAA;

    let mut scenario = test_scenario::begin(admin);
    {
        target_module::initialize(test_scenario::ctx(&mut scenario));
    };

    // ========================================
    // STEP 1: ENABLER (Finding B)
    // Execute action that creates the postcondition
    // ========================================
    test_scenario::next_tx(&mut scenario, attacker);
    {
        let mut shared_obj = test_scenario::take_shared<target_module::Pool>(&scenario);
        // Execute enabler action that creates the precondition for Finding A
        target_module::enabler_action(
            &mut shared_obj,
            /* enabler args */
            test_scenario::ctx(&mut scenario),
        );
        test_scenario::return_shared(shared_obj);
    };

    // ========================================
    // VERIFY POSTCONDITION CREATED
    // Assert the precondition for Finding A is now met
    // ========================================
    test_scenario::next_tx(&mut scenario, attacker);
    {
        let shared_obj = test_scenario::take_shared<target_module::Pool>(&scenario);
        // Verify the enabler created the necessary state
        let postcondition_value = target_module::get_state(&shared_obj);
        assert!(postcondition_value == expected_postcondition, 0);
        test_scenario::return_shared(shared_obj);
    };

    // ========================================
    // STEP 2: BLOCKED FINDING (Finding A)
    // Execute previously-blocked attack using postcondition
    // ========================================
    test_scenario::next_tx(&mut scenario, attacker);
    {
        let mut shared_obj = test_scenario::take_shared<target_module::Pool>(&scenario);
        // Execute the attack that was previously blocked
        target_module::blocked_attack(
            &mut shared_obj,
            /* attack args */
            test_scenario::ctx(&mut scenario),
        );
        test_scenario::return_shared(shared_obj);
    };

    // ========================================
    // VERIFY CHAIN IMPACT
    // Combined impact should exceed either finding alone
    // ========================================
    test_scenario::next_tx(&mut scenario, attacker);
    {
        let profit_coin = test_scenario::take_from_sender<Coin<SUI>>(&scenario);
        let profit = coin::value(&profit_coin);
        assert!(profit > 0, 0);
        test_scenario::return_to_sender(&scenario, profit_coin);
    };

    test_scenario::end(scenario);
}
```

### Chain Dismissal Requirements

To mark a chain hypothesis as FALSE_POSITIVE, you MUST:
1. Prove enabler finding does NOT create the postcondition, OR
2. Prove blocked finding still blocked EVEN WITH the postcondition, OR
3. Prove chain sequence is impossible due to object ownership/access/state constraints

Each proof requires [PROD-ONCHAIN], [PROD-SOURCE], or [CODE] evidence -- no [MOCK] evidence allowed.

### Bidirectional Chain Analysis (Rule 6 Extension)
For chain hypotheses where enabler OR blocked finding involves a semi-trusted role (operator/keeper/crank):
Verify BOTH directions: (1) role executes chain to harm users, AND (2) users exploit role timing/ordering to trigger chain.
If only one direction analyzed -> verdict CANNOT be FALSE_POSITIVE. Return CONTESTED with note: "Chain bidirectional analysis incomplete."

---

## Chain Hypothesis Protection

> **CRITICAL**: Chain hypotheses receive elevated protection because they represent multi-step attacks initially missed.

### Protection Rules

1. **RAG >= 6/8 + Chain**: Cannot be dismissed as FALSE_POSITIVE
2. **3+ agents flagged + Chain**: Need PRODUCTION evidence to refute
3. **Chain PoC MUST test full sequence**: Both enabler AND blocked finding

---

## Sui-Specific Testing Considerations

### No Fork Testing Equivalent

Sui does not have an Anvil-like mainnet fork. Use these alternatives:

1. **Published package testing**: If the protocol is deployed on testnet/mainnet, use the published package address in Move.toml dependencies and write tests against the actual on-chain bytecode. Evidence tag: [PROD-PUBLISHED].

2. **Object state dumps**: Use Sui RPC to dump production object state:
```bash
sui client object <object_id> --json > object_dump.json
```
Then reconstruct the object state in test_scenario setup. Evidence tag: [PROD-ONCHAIN] for the dump, [CODE] for the reconstructed test.

3. **Package source verification**: Use Sui Explorer to verify published package source matches audited code. Evidence tag: [PROD-SOURCE].

### PTB-Aware Testing

Programmable Transaction Blocks (PTBs) allow composing multiple Move calls atomically in a single Sui transaction. When testing:

- **Atomic composition**: Multiple commands in a PTB share the same transaction context. Objects returned by one command can be passed to the next. In test_scenario, simulate this by performing multiple operations within a single `next_tx` block.
- **Move call chaining**: PTB allows calling functions from different packages in sequence. Test cross-package interactions within a single block.
- **Object passing between commands**: PTB can split a Coin, use part in one call and part in another. Simulate with explicit `coin::split` in tests.
- **Gas estimation**: PTB gas is the sum of all commands. Complex atomic exploits may hit gas limits on mainnet that test_scenario does not enforce.

### Shared Object Concurrency Testing

test_scenario processes transactions sequentially, but on mainnet, transactions touching the same shared object go through consensus and may be reordered. To test ordering sensitivity:

1. **Test both orderings**: Write two tests with the same operations but different `next_tx` ordering. If outcomes differ, the protocol is ordering-sensitive.
2. **Test interleaved operations**: Alternate between two actors (user and attacker) operating on the same shared object to simulate concurrent access.
3. **Document ordering assumptions**: If the protocol assumes "admin action happens before user action," flag this as an ordering dependency.

---

## Dual-Perspective Verification (MANDATORY)

### Phase 1 - ATTACKER: Assume you ARE the attacker.
- What is the complete transaction sequence?
- What objects do you need to create/acquire?
- What is the profit/damage with real coin amounts?
- Can you compose multiple operations in a single PTB for atomicity?
- Why would this succeed? (Which access control or validation is missing/wrong?)

### Phase 2 - DEFENDER: Assume you are the protocol team.
- What capability check prevents this?
- What object ownership model blocks unauthorized access?
- What module-level access restriction (`public(package)` vs `public`) prevents external calls?
- Why is this safe by design?

### Phase 3 - VERDICT: Which argument won?

---

## Realistic Parameter Validation

Substitute ACTUAL protocol constants (basis points, fee rates, thresholds, maximum values).
Apply Rule 10: Use worst realistic operational state, not current snapshot.

```
State: 'With real constants [fee_bps=X, max_leverage=Y, tvl=Z] at worst-state
[max_users, max_positions], bug triggers when [condition]'
OR: 'With real constants, bug does NOT trigger because [reason]'
```

---

## Anti-Downgrade Guard (MANDATORY for VS/BLIND findings)

When verifying a finding from Validation Sweep ([VS-*]) or Blind Spot Scanner ([BLIND-*]), you MUST apply Rule 13's 5-question test BEFORE downgrading severity or marking FALSE_POSITIVE:

1. **Who is harmed** by this design gap?
2. **Can affected users avoid** the harm?
3. **Is the gap documented** in protocol docs?
4. **Could the protocol achieve the same goal** without this gap?
5. **Does the function fulfill its stated purpose completely?**

**HARD RULE**: If the finding shows Module A has protection X but Module B lacks it for the same user action -> defense parity gap, NOT "by design". Minimum severity: Medium.

---

## New Observations (MANDATORY)

If during verification you discover a NEW bug, object ownership gap, or edge case NOT covered by any existing hypothesis, document it under:

### New Observations
- [VER-NEW-1]: {title} -- {module::function} -- {brief description}

These will be reviewed by the orchestrator for possible inclusion as new findings.

---

## Error Trace Output (MANDATORY for CONTESTED/FALSE_POSITIVE)

When verdict is CONTESTED or FALSE_POSITIVE, document the failure details:

### Error Trace
- **Failure Type**: ABORT_CODE / OBJECT_NOT_FOUND / TYPE_MISMATCH / BORROW_ERROR / ARITHMETIC / UNEXPECTED_STATE
- **Location**: {module}::{function} (approximate line in source)
- **Error Code**: {Move abort code or custom error constant, if any}
- **State at Failure**: {key object fields and their values when test failed}
- **Investigation Question**: {What would need to be answered to resolve this}

---

## Bidirectional Role Analysis (MANDATORY)

> **CRITICAL**: Semi-trusted role findings CANNOT be marked REFUTED unless BOTH directions are analyzed.

### HALT CONDITIONS for Semi-Trusted Role Findings

Before marking ANY finding involving OPERATOR/KEEPER/CRANK roles as REFUTED:

- [ ] **Direction 1 analyzed**: ROLE -> USER harm scenarios
- [ ] **Direction 2 analyzed**: USER -> ROLE exploitation
- [ ] **Precondition Griefability table completed**: All role function preconditions checked
- [ ] **User exploitation scenarios documented**

### Direction 2 Enforcement

If Direction 2 (USER -> ROLE) is NOT analyzed:
- CANNOT return REFUTED
- MUST return CONTESTED with note: "Direction 2 not analyzed"
- Finding flagged for depth review

---

## Output Format

### CONFIRMED

```markdown
## Verdict: CONFIRMED

### Bug Mechanism Verified
{Explain what the test_scenario test proves in 2-3 sentences}

### Test Code
{Full Move test function}

### Test Output
{Relevant assertions and logged values from `sui move test`}

### Key Evidence
| Metric | Value |
|--------|-------|
| Before | {value} |
| After | {value} |
| Expected | {value} |
| Difference | {calculation} |

### Evidence Audit
| Claim | Evidence Source | Tag | Valid for REFUTED? |
|-------|-----------------|-----|-------------------|

### RAG Evidence
- **Attack Vectors Consulted**: [list]
- **Similar Exploits Found**: [count]
- **Historical Precedent**: [description]

### Severity: {LEVEL}
{Justification in 1-2 sentences}
```

### FALSE_POSITIVE

```markdown
## Verdict: FALSE_POSITIVE

### Attempts Made

**Attempt 1:**
- Approach: {description}
- Result: {what happened -- include abort codes}
- Learning: {insight}

**Attempt 2:**
- Approach: {description}
- Result: {what happened}
- Learning: {insight}

**Attempt 3:**
- Approach: {description}
- Result: {what happened}
- Learning: {insight}

### Evidence Audit
| Claim | Evidence Source | Tag | Valid for REFUTED? |
|-------|-----------------|-----|-------------------|

### Why It Is Not a Bug
{Explain the actual behavior and why hypothesis was wrong in 2-3 sentences}

### Error Trace
- **Failure Type**: {type}
- **Location**: {location}
- **Error Code**: {code}
- **State at Failure**: {state}
- **Investigation Question**: {question}
```

### CONTESTED

```markdown
## Verdict: CONTESTED

### Evidence Status
| Checkpoint | Status | Details |
|------------|--------|---------|
| External package behavior verified against PRODUCTION | YES/NO | {details} |
| All entry functions checked | YES/NO | {details} |
| Object ownership model verified | YES/NO | {details} |
| Shared object access control confirmed | YES/NO | {details} |

### Evidence Audit
| Claim | Evidence Source | Tag | Valid for REFUTED? |
|-------|-----------------|-----|-------------------|

### Why This Cannot Be REFUTED
{Explain what evidence is missing to definitively rule out the bug}

### Escalation Required
- [ ] Fetch published package source for {external dep}
- [ ] Dump production object state for {object}
- [ ] Check additional entry function paths: {list}

### Error Trace
- **Failure Type**: {type}
- **Location**: {location}
- **Error Code**: {code}
- **State at Failure**: {state}
- **Investigation Question**: {question}
```

---

## Insufficient Evidence (HALT CONDITIONS)

Before marking REFUTED, check ALL boxes:
- [ ] External package behavior verified against PRODUCTION (not mock)
- [ ] Attack path checked on ALL public entry functions that access the same shared objects
- [ ] Profit calculated with attacker HOLDING tokens (not just transferring in)
- [ ] Missing precondition documented (type: STATE / ACCESS / TIMING / EXTERNAL / BALANCE)
- [ ] Searched other findings for matching postconditions (chain analysis integration)
- [ ] Object ownership verified in source (not assumed from naming)
- [ ] Capability access control verified for ALL shared object mutation paths
- [ ] Dynamic field access patterns verified (correct key types, no collisions)

### Evidence That Does NOT Count
- "Mock module shows X" -- mocks are not production behavior
- "Standard Coin<T>" -- may be wrapped in custom module with hooks/restrictions
- "Attacker loses by sending coins" -- may profit via position held in pool
- "Function is `public(package)`" -- may be callable via CPI from another module in the same package
- "Requires AdminCap" -- AdminCap may have `store` ability and be transferable
- "Attacker cannot acquire X" -- another finding may CREATE this condition
- "Object is owned by admin" -- ownership may be transferable if object has `store`
