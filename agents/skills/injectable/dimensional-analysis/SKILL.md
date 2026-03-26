---
name: "dimensional-analysis"
description: "Protocol Type Trigger MIXED_DECIMALS (mulDiv/mulWad/rayMul + mixed scale factors detected) - Inject Into depth-token-flow, depth-state-trace"
---

# Injectable Skill: Dimensional Analysis

> **Protocol Type Trigger**: `MIXED_DECIMALS` (detected when: `mulDiv|mulWad|divWad|rayMul|rayDiv|FullMath` AND any of `1e6|1e8|decimals()|10**6|10**8` in same scope)
> **Inject Into**: depth-token-flow, depth-state-trace
> **Language**: EVM only (Solidity fixed-point arithmetic)
> **Finding prefix**: `[DA-N]`
> **Added in**: v1.1.0

## Orchestrator Decomposition Guide
- Phase 1 + 2 (Vocabulary + Annotation): depth-token-flow (token scale tracking at entry/exit)
- Phase 3 (Propagation): depth-state-trace (arithmetic chains through storage)
- Phase 4 (Validation): both agents apply Phase 4 rejection list independently

## When This Skill Activates

Recon detected MIXED_DECIMALS: the protocol uses fixed-point arithmetic (`mulDiv`, `mulWad`, `rayMul`, etc.) AND references values with different decimal representations. Classic examples: Chainlink prices (8 decimals) used in WAD (18-decimal) arithmetic; USDC (6 decimals) as collateral in a vault that internally tracks in WAD; a price aggregator that normalizes some but not all feeds.

This skill systematically finds dimension/unit mismatches — e.g., where `price[8-dec] * amount[18-dec] = result[26-dec]` is treated as a WAD result without the required `/ 1e8` normalization, causing funds to be mispriced by factors of 10^10 or more.

---

## Phase 1: Dimension Vocabulary Discovery (depth-token-flow)

### 1.1 Scale Constant Inventory
Search (excluding test/, lib/, mocks/):
```
grep: 1e6, 1e8, 1e18, 1e27, 10**6, 10**8, 10**18, 10**27
      WAD, RAY, BASE, UNIT, PRECISION, SCALE, DENOMINATOR
      decimals(), DECIMALS, _decimals
```

Build a dimension vocabulary table:
| Constant | Numeric Value | Inferred Scale | Locations |
|----------|--------------|----------------|-----------|
| `1e18` | 10^18 | WAD / 18-decimal | ... |
| `1e6` | 10^6 | USDC-scale | ... |
| `feed.decimals()` | 8 (typical Chainlink) | Chainlink price | ... |

### 1.2 Token and Feed Decimal Survey
| Asset | Decimals Source | Value | Dynamic? |
|-------|----------------|-------|---------|
| (each token) | hardcoded / `decimals()` call | 6/8/18/other | YES/NO |
| (each Chainlink feed) | `feed.decimals()` | 8 (verify per-feed!) | YES |

**Red flag**: If `decimals()` is called at runtime and used in arithmetic without caching → the protocol must normalize at EVERY arithmetic point, creating many potential miss sites.

---

## Phase 2: Expression Annotation (depth-token-flow + depth-state-trace)

For EVERY `mulDiv(a, b, c)`, `mulWad(a, b)`, `divWad(a, b)`, `rayMul(a, b)`, and direct `*` / `/` involving Phase 1 constants:

**Annotation format**: Write the inferred unit for each operand:
```
// DA: price[USD/ETH, 8-dec] × amount[ETH, 18-dec] = [USD, 26-dec] ← needs / 1e8
uint256 value = price * amount;  // BUG if consumed as WAD output
```

Key checks:
- `mulWad(a, b)`: both operands MUST be 18-dec. If `b` is a Chainlink price (8-dec) → result is 10^10x too small.
- `mulDiv(a, b, c)`: output scale = `(a_scale × b_scale) / c_scale`. Is that scale correct at the consumption site?
- `a / 1e18`: if `a` was already WAD this is correct. If `a` is 8-dec Chainlink price, result is 10^10x too small.
- `mulWad(price, amount)` where price came from Chainlink without `* 1e10` upscaling → systematic undervaluation.

---

## Phase 3: Propagation Tracing (depth-state-trace)

For each expression with a dimensional annotation from Phase 2:

### 3.1 State Variable Propagation
- Is the result stored in a state variable? Does the variable name imply a unit (e.g., `priceWad`)?
- Does the name match the actual unit? Mismatch → [DA-N] candidate.
- Which functions READ this variable downstream? Do they assume the stored unit?

### 3.2 Cross-Function Boundary Checks
| Call Site | Value Passed | Caller's Scale | Callee's Assumed Scale | Mismatch? |
|-----------|-------------|----------------|----------------------|-----------|

For each YES: trace to terminal impact (wrong amount transferred, wrong collateral ratio, wrong liquidation threshold).

Tag: `[TRACE: price[8-dec] stored as priceWad → mulWad(priceWad, amount) → result 10^10x too small → withdrawal undervalued]`

### 3.3 Entry/Exit Normalization Gaps
- At every token ENTRY (deposit, receive, transferFrom): is the amount normalized to the internal scale?
- At every token EXIT (withdraw, transfer, mint): is the internal value denormalized to token units?
- Are normalization constants hardcoded (fragile) or derived from `decimals()` (correct but must verify)?

---

## Phase 4: Validation and Severity (both agents)

### 4.1 Rationalization Rejection List (MANDATORY before closing any [DA-N] finding as REFUTED)

| Rationalization | Why It Fails |
|----------------|-------------|
| "The formula appears correct" | State the units explicitly — correct formula ≠ correct units |
| "All tokens use 18 decimals" | Verify per-token: USDC=6, WBTC=8, Chainlink=8 are common in-scope assets |
| "Tests pass" | Test mocks use 18 decimals; production tokens use 6. Test pass ≠ dimensional safety |
| "Standard pattern used elsewhere" | The pattern may carry the same bug everywhere; verify units at THIS call site |
| "The ratio cancels out" | Valid ONLY if BOTH numerator and denominator undergo identical scale — prove it explicitly |

### 4.2 Severity Calibration
| Mismatch Magnitude | Asset Type | Example Impact | Severity |
|-------------------|------------|----------------|---------|
| 10^12 (6-dec vs 18-dec) | Token price / exchange rate | Collateral massively mispriced | Critical |
| 10^10 (8-dec vs 18-dec) | Chainlink price in WAD context | Price inflated/deflated 10^10x | High |
| 10^2 or less | Internal weights | Bounded rounding error | Medium/Low |
| Any | View-only path | No fund loss possible | Low cap |

### 4.3 Boundary Substitution (MANDATORY for each confirmed mismatch)
- `USDC_amount = 1e6` (1 USDC) used as WAD input → `mulWad(1e6, X) = X × 1e6 / 1e18 = 0` (rounds to zero)
- `chainlink_price = 1e8` ($1 in 8-dec) used as WAD → 10^10 overstatement of value
- `MAX_UINT / 1e18` path → check for overflow when mismatch causes intermediate multiplication

Tag: `[BOUNDARY: USDC_amount=1e6 as WAD input → mulWad result rounds to 0 → user receives nothing]`
Tag: `[VARIATION: token.decimals()=6→18 → 10^12 change in collateral valuation]`
