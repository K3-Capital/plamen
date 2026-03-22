---
name: "move-safety-core-directives"
description: "Lightweight core directives for Sui Move always-required skills — injected into every breadth agent. Full methodology lives in the dedicated Move-Safety Agent."
type: "core-directive"
---

# Move Safety Core Directives (Sui)

> **Purpose**: These are the INVENTORY + FLAG directives extracted from the 4 always-required Sui skills (ABILITY_ANALYSIS, BIT_SHIFT_SAFETY, TYPE_SAFETY, OBJECT_OWNERSHIP). Every breadth agent receives these to flag Move-specific patterns for depth review. The full trace methodology lives in the dedicated Move-Safety Agent (spawned separately).
> **Total**: ~130 lines (vs ~900 lines for 4 full skills)

## 1. Ability Inventory (from ABILITY_ANALYSIS)

Enumerate ALL structs. For each:

| Module | Struct | Abilities | Has `id: UID`? | Is Object? | Transferable? | Notes |
|--------|--------|-----------|----------------|------------|---------------|-------|

**Flag for depth review**:
- Struct with `copy` that holds `Balance<T>` or represents economic value → [FLAG:ABILITY-COPY-VALUE]
- Struct with `drop` that represents an obligation (receipt, hot potato) → [FLAG:ABILITY-DROP-OBLIGATION]
- Object (`key`) with `store` that should restrict transfers → [FLAG:ABILITY-EXCESS-STORE]
- Hot potato (no abilities) with no consumption path in the protocol → [FLAG:ABILITY-STUCK-HOTPOTATO]
- `copy + key` combination (impossible in Sui — compilation error) → [FLAG:ABILITY-INVALID-COMBO]

## 2. Bit Shift Inventory (from BIT_SHIFT_SAFETY)

**GREP**: Search all `.move` files for `<<` and `>>`.

For each shift operation:

| Location | Operand Type | Bit Width | Shift Amount Source | User-Controllable? | Bounded? |
|----------|-------------|-----------|--------------------|--------------------|----------|

**Flag for depth review**:
- Shift amount is user-controllable or computed AND unbounded → [FLAG:SHIFT-UNBOUND]
- Shift amount is constant but >= bit width → [FLAG:SHIFT-OVERFLOW-CONST]
- Shift in public/entry function with external input path → [FLAG:SHIFT-EXTERNAL]

## 3. Generic Type Inventory (from TYPE_SAFETY)

**GREP**: Search all `.move` files for `fun .*<` to find every generic function.

For each generic function:

| Function | Module | Type Params | Constraints | Entry? | Creates/Destroys T? |
|----------|--------|-------------|-------------|--------|---------------------|

**Flag for depth review**:
- Generic function accepting `Coin<T>` or `Balance<T>` without verifying T matches expected type → [FLAG:TYPE-COIN-CONFUSION]
- Generic with only `store` constraint where `key` or specific type is needed → [FLAG:TYPE-WEAK-CONSTRAINT]
- Generic entry function callable by anyone with attacker-chosen type → [FLAG:TYPE-ATTACKER-CHOSEN]
- One-Time Witness (OTW) type used outside `init()` or not consumed → [FLAG:TYPE-OTW-LEAK]

## 4. Object Ownership Inventory (from OBJECT_OWNERSHIP)

Classify every object (`key` ability) by ownership model:

| Object | Ownership | Created Via | Has `store`? | Transfer Restricted? | Dynamic Fields? |
|--------|-----------|-------------|-------------|---------------------|-----------------|

**Flag for depth review**:
- Shared object mutated without access control → [FLAG:OBJ-SHARED-UNGUARDED]
- Object with `store` that should NOT be freely transferable → [FLAG:OBJ-EXCESS-TRANSFER]
- Object deleted via `object::delete` without cleaning up dynamic fields → [FLAG:OBJ-DELETE-DIRTY]
- Owned object wrapped/unwrapped in ways that change its accessibility → [FLAG:OBJ-WRAP-ESCAPE]
- Object with `Balance<T>` field but no withdrawal function → [FLAG:OBJ-STRANDED-BALANCE]

## Self-Check

Before completing analysis, verify you produced inventories for ALL 4 sections above. Missing inventories = missing coverage for Move-specific vulnerability classes.
