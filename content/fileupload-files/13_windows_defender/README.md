# 13_windows_defender — authorized-engagement methodology + benign probes

**Safe PoC** -> x8bitranjit

## What this folder IS

The Windows-security-stack knowledge pack for an **authorized** red-team engagement
(ROE-covered): how Defender's protection layers map to MITRE ATT&CK, non-evasive
inventory probes that use Defender's OWN cmdlets, the exclusions/ASR audit that
produces real reportable findings, and the blue-team detection mirror for every
technique class.

## What this folder deliberately does NOT contain

- Working AMSI-patch code (memory patching of the scan interface)
- Obfuscation engines, crypters, encrypted payload delivery
- Any artifact whose purpose is to defeat a security control rather than
  measure or report on it

**Why:** bug bounty programs do not cover endpoint-AV evasion, and working
evasion tooling is outside this lab's benign discipline. When an authorized
engagement requires those techniques, they come from your employer's approved
toolset under ROE — not from a public PoC lab. Public research pointers are
given by author/technique name so you can study from the original sources.

## Files

| File | Purpose |
|---|---|
| `defender_surface_map.txt` | every protection layer + what it inspects + MITRE mapping |
| `benign_inventory_probes.txt` | non-evasive recon of the security stack (Defender's own cmdlets) |
| `asr_exclusions_audit.txt` | overbroad exclusions / disabled ASR = the reportable misconfiguration |
| `execution_tradecraft_taxonomy.txt` | technique CLASSES with MITRE IDs + research pointers |
| `detection_mapping.txt` | blue-team mirror: each class -> the event/log that catches it |
| `engagement_rules.txt` | when AV testing is in scope at all + cleanup ledger rules |

## Discipline

Bug bounty: endpoint AV is out of scope — this folder is for authorized
engagements only. Every command in these files is inventory, echo, or a
Defender-cmdlet query. Nothing here impairs, patches, or evades anything.
