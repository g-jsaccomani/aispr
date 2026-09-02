# Validation: Epistemological Constraints & Type Invariants

## Date
2026-09-02T18:37:15.510419+00:00

## Git Commit Before Test
`9fc8b7490f8907a2843586121a340199e82bbfc8`

## Environment
macOS (Darwin 24.6.0), Python 3.14.5, AISPR Specification 2.0.0

## Practical Invariant Checks

| Invariant / Check | Expected Behavior | Observed Result | Result |
| :--- | :--- | :--- | :--- |
| **LIVE without evidence** | Fail validation with ValueError | `Raised ValueError: 1 validation error for SecurityFinding
  Value error, LIVE finding int` | PASS |
| **LIVE with simulation evidence** | Fail validation with ValueError | `Raised ValueError: 1 validation error for SecurityFinding
  Value error, LIVE finding int` | PASS |
| **SIMULATION with VERIFIED evidence** | Fail validation with ValueError | `Raised ValueError: 1 validation error for Evidence
  Value error, Simulation integrity vi` | PASS |
| **FALLBACK with VERIFIED evidence** | Fail validation with ValueError | `Raised ValueError: 1 validation error for Evidence
  Value error, Simulation integrity vi` | PASS |
| **Invalid Execution Mode string** | Fail fast with ValueError | `Raised ValueError: 1 validation error for SecurityFinding
execution_mode
  Value error, I` | PASS |
| **Zero evidence propagated_confidence == 0.0** | propagated_confidence == 0.0 across all non-live modes | `All modes returned 0.0: True` | PASS |

---

## Technical Enforcements
1. Non-live findings (SIMULATION, FIXTURE, MOCK, FALLBACK) are strictly prohibited from holding VERIFIED evidence.
2. LIVE findings require real verified evidence and authentic provenance.
3. Zero evidence evaluates strictly to 0.0 propagated technical confidence.
4. Invalid enum strings fail closed with immediate ValueError, eliminating silent fallbacks.
