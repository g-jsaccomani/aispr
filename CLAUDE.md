# CLAUDE.md - GLOBAL RULES FOR THIS REPOSITORY

These rules are permanent and apply to every phase of AISPR development, auditing, and maintenance:

1. **Work hands-on.** Clone the repo, install dependencies, and RUN the code.
   Never report a result you did not personally execute.
   ```bash
   cd /home/claude && rm -rf aispr && git clone https://github.com/g-jsaccomani/aispr.git
   cd aispr && export PYTHONPATH=$(pwd)
   ```

2. **Every claim in your final report must be backed by pasted terminal output with a visible exit code.**
   "It should work" is not acceptable.

3. **Never weaken, skip, or delete a test to make a suite pass.**
   If a test is wrong, fix the test and say explicitly why it was wrong.

4. **The Epistemic Truthfulness Model is inviolable.**
   No new code may allow `SIMULATION` / `MOCK` / `FIXTURE` / `FALLBACK` evidence to be marked `VERIFIED`, or allow `confidence > 0` with zero evidence.

5. **All scanning stays read-only.**
   Any write operation must be gated behind an explicit human approval token.

---

## Primary Verification Commands

Run the full verification suite before making claims:

```bash
# 1. Bytecode Compilation (Python 3.10+)
python3 -m compileall .

# 2. Epistemological Truthfulness Gate (23 tests)
python3 -m unittest agentic/tests/test_truthfulness_gate.py -v

# 3. Full Test Suites (244 tests total)
make test
# OR individually:
python3 -m unittest discover -s audit/tests -p "test_*.py"
python3 -m unittest discover -s agentic/tests -p "test_*.py"

# 4. Regulatory Control Contract Validation (104 contracts)
./aispr controls validate

# 5. Git Hygiene Check
git diff --check
```

See [`docs/CLAUDE_CRITICAL_DOUBLE_CHECK_HANDOFF.md`](docs/CLAUDE_CRITICAL_DOUBLE_CHECK_HANDOFF.md) for full architecture context and handoff details.
