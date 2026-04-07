# Phase 4b Required Artifacts — Soroban (Thorough Mode)

> **Purpose**: Static manifest of files that MUST exist in {SCRATCHPAD}/ before Phase 4b exits.
> **Enforcement**: The orchestrator runs `ls {SCRATCHPAD}/` and checks EVERY line below.
> **This file is READ-ONLY** — the orchestrator MUST NOT modify it. If an artifact is missing,
> spawn the responsible agent. Do NOT mark it as "skipped" or "N/A" in the checkpoint.

## Required Artifacts (Thorough Mode)

| File | Producer | Phase |
|------|----------|-------|
| `depth_token_flow_findings.md` | depth-token-flow agent | 4b iter 1 |
| `depth_state_trace_findings.md` | depth-state-trace agent | 4b iter 1 |
| `depth_edge_case_findings.md` | depth-edge-case agent | 4b iter 1 |
| `depth_external_findings.md` | depth-external agent | 4b iter 1 |
| `blind_spot_a_findings.md` | Scanner A | 4b iter 1 |
| `blind_spot_b_findings.md` | Scanner B | 4b iter 1 |
| `blind_spot_c_findings.md` | Scanner C | 4b iter 1 |
| `validation_sweep_findings.md` | Validation Sweep | 4b iter 1 |
| `design_stress_findings.md` | Design Stress Testing | 4b iter 1 |
| `symmetric_pairs.md` | Orchestrator (pre-depth) | 4b pre |
| `perturbation_findings.md` | Finding Perturbation Agent | 4b post |
| `skill_execution_gaps.md` | Skill Execution Checklist | 4b post |
| `confidence_scores.md` | Scoring agent | 4b scoring |
| `confidence_distribution.md` | Orchestrator | 4b scoring |
| `adaptive_loop_log.md` | Orchestrator | 4b exit |
| `phase4b_manifest.md` | Orchestrator | 4b exit |
| `rag_validation.md` | RAG Sweep agent | 4b.5 |

## Niche Agent Artifacts (if triggered)

Check `template_recommendations.md` → Niche Agents section. For each `Required: YES`:
| Flag | File |
|------|------|
| MISSING_EVENT | `niche_event_completeness_findings.md` |
| sync_gaps >= 1 from Phase 4a.5 | `niche_semantic_gap_findings.md` |
| HAS_MULTI_CONTRACT | `niche_semantic_consistency_findings.md` |
| HAS_SIGNATURES | `niche_signature_audit_findings.md` |
| HAS_DOCS | `niche_spec_compliance_findings.md` |

## Checkpoint Protocol

The orchestrator MUST execute this BEFORE writing `checkpoint_postdepth.md`:

```
missing = []
for each file in Required Artifacts table:
    if not exists({SCRATCHPAD}/{file}):
        missing.append(file)

for each niche agent marked Required: YES in template_recommendations.md:
    if not exists({SCRATCHPAD}/{niche_file}):
        missing.append(niche_file)

if len(missing) > 0:
    log("PHASE 4b INCOMPLETE: missing {missing}")
    for each missing file:
        spawn the responsible agent (see Producer column)
    re-check after agents complete

ASSERT len(missing) == 0 before proceeding to Phase 4c
```
