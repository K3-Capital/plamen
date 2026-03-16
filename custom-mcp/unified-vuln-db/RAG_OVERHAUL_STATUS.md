# RAG Overhaul — unified-vuln-db

**Date**: 2026-01-29
**Status**: Code changes complete, awaiting re-index and verification

---

## What Was Done

### Problem
The RAG returned empty `root_causes`, `attack_vectors`, and `similar_findings` because:
1. Solodit indexer hard-coded `vulnerable_code=""`, `recommendation=""`, never parsed the `content` markdown field
2. `extract_reasoning_material()` read `r.get("root_cause")` from metadata, but `to_metadata()` never includes those fields — they only exist in the `document` text blob
3. HuggingFace source contributed generic labeled code with no context, diluting results

### Files Changed

| File | Change |
|------|--------|
| `unified_vuln/sources/huggingface.py` | Gutted to no-op stub |
| `unified_vuln/sources/__init__.py` | Removed huggingface import |
| `unified_vuln/indexer.py` | Removed huggingface from CLI and index logic |
| `unified_vuln/sources/solodit.py` | Added `parse_content_sections()` — extracts root_cause, impact, recommendation, attack_vector, vulnerable_code from content markdown. Updated `parse_finding()` to populate all Vulnerability fields. |
| `unified_vuln/server.py` | Added `parse_document_sections()` to parse `## Header` sections from stored documents. Rewrote `extract_reasoning_material()` to read from both metadata AND document text. Returns `similar_findings`, `methodology_hints`, `severity_distribution`. Updated `get_similar_findings` handler similarly. |

### Files NOT Changed (confirmed no changes needed)
- `unified_vuln/schema.py` — already has all fields (root_cause, attack_vector, etc.)
- `unified_vuln/database.py` — already stores/returns document text

---

## Commands To Run (new terminal)

```powershell
cd custom-mcp/unified-vuln-db

# Wipe old data
python -m unified_vuln.indexer clear

# Re-index with new parser (solodit needs SOLODIT_API_KEY env var)
python -m unified_vuln.indexer index -s solodit --max-pages 10
python -m unified_vuln.indexer index -s defihacklabs
python -m unified_vuln.indexer index -s immunefi

# Check counts
python -m unified_vuln.indexer stats
```

Then **restart Claude Code** to reload the MCP server.

---

## Verification (ask Claude to run after restart)

1. `get_knowledge_stats()` → should show 0 huggingface entries, populated solodit/defihacklabs/immunefi
2. `get_root_cause_analysis("reentrancy")` → `root_causes` and `similar_findings` should be non-empty
3. `get_similar_findings("safeMint callback reentrancy")` → findings should have `root_cause`, `vulnerable_code`, `recommendation` fields populated

---

## If Verification Fails

If `root_causes` is still empty after re-indexing solodit, the Solodit API `content` field may not use the markdown section headers we're parsing (`## Root Cause`, `## Recommendation`, etc.). In that case:

1. Inspect a raw cached API response in `data/solodit_cache/` to see the actual content format
2. Adjust the regex patterns in `parse_content_sections()` in `sources/solodit.py` to match

The `parse_document_sections()` in `server.py` should always work since it reads the `## Header` format produced by `Vulnerability.to_document()` — so even if solodit content has no headers, any field populated at index time (root_cause, recommendation, etc.) will be recoverable from the stored document.
