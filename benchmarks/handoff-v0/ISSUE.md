# Finish the promotion evidence gate

Implement `evaluatePromotionGate` in `src/promotion-gate.js`.

The function decides whether a named subject may be promoted. Every required check must have current passing evidence for the exact subject. Missing, mismatched, stale, unknown, or failed evidence must deny promotion. The output is `{ allowed, blockers }`; blockers contain `check_id` and `reason` and are sorted by `check_id` so repeated evaluations are deterministic.

Do not mutate the policy or evidence inputs. Keep the package dependency-free and preserve the exported API. `npm test` must pass.
