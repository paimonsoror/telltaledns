# Pass 10: synthesis

**Output:** `docs/review/v0.2.0/10-synthesis.md` (no patches)

Run this last, after passes 01-09. Read their reports (not the code again, except to settle a
conflict between two of them).

## Write
1. **Overall assessment** (one page): how TelltaleDNS v0.2.0 stands against its own goals
   and the owner's priorities, and how close it is to the v1.0 gate (`docs/v1-gate.md`).
2. **What to protect:** the strengths that recur across passes (design choices, practices,
   tests) and should survive future changes. Cite the passes.
3. **Themes:** problems that show up in more than one area (for example, error
   classification, unbounded growth, test gaps of one kind), with the findings that belong
   to each.
4. **Ranked plan:** every critical and high finding, then the medium ones worth doing now,
   ordered by impact on the owner's priorities and by effort. Mark dependencies between
   findings and patches that conflict.
5. **Questions for the owner:** merged and de-duplicated from all passes.
6. **Coverage:** what no pass reviewed, and what you'd review next.
