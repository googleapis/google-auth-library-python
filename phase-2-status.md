# 🧠 Phase 2 — Expansion & Elevation

**Status:** 🚀 In Progress  
**Start Date:** April 2025  
**Milestone:** Expand credential logic, test coverage, CI automation, and contributor readiness.

---

## ✅ Objective

Build on Phase 1 by expanding support for new credential types, strengthening validation, refactoring for reusability, expanding test coverage, and preparing the repo for real-world usage and potential distribution.

---

## 📋 Task Table

| ID | Category | Description | Dependencies | Status |
|----|----------|-------------|--------------|--------|
| P2-01 | Code Expansion | Extend `IdentityPoolCredentials` to support real token injection (beyond mocks) | Phase 1 complete | 🔲 Not Started |
| P2-02 | Code Expansion | Support additional credential types (e.g. GDCH, Workload Identity Federation) | P2-01 | 🔲 Not Started |
| P2-03 | Security & Input Validation | Harden input validation for env vars, file paths | Phase 1 base | 🔲 Not Started |
| P2-04 | Refactor & Simplify | Refactor token logic into a shared helper/module | P2-01 | 🔲 Not Started |
| P2-05 | Testing | Expand `test_identity_pool.py` with edge-case tests | P2-01, P2-03 | 🔲 Not Started |
| P2-06 | Linux Validation | Run `run_tests.sh` on clean Linux environment | Phase 1 | 🔲 Not Started |
| P2-07 | Documentation | Create `CONTRIBUTING.md` with test instructions & PR workflow | Phase 1 | 🔲 Not Started |
| P2-08 | Docs | Expand README with contributor setup section | P2-07 | 🔲 Not Started |
| P2-09 | Mock Framework | Extract reusable mocks to `rewired/mocks/` or similar | P2-01, P2-04 | 🔲 Not Started |
| P2-10 | Milestone Tracking | Create `phase-2-status.md` to log all of this | Phase 2 kickoff | ✅ Done |
| P2-11 | Test Framework | Fix teardown in `test_pluggable.py` and reduce flakiness | Phase 1 tests | 🔲 Not Started |
| P2-12 | Test Expansion | Add coverage for `test_sts.py`, `test_credentials.py` | P2-01 | 🔲 Not Started |
| P2-13 | Fixture Reuse | Build global test fixtures like `make_credentials()` | P2-11, P2-12 | 🔲 Not Started |
| P2-14 | CI: Coverage | Integrate `pytest-cov`, generate coverage reports | P2-11, P2-12 | 🔲 Not Started |
| P2-15 | Packaging | Start preparing `google-auth-rewired` for PyPI | Phase 2 stable | 🔲 Not Started |
| P2-16 | CI: Matrix | Add GitHub Actions matrix for Python versions / OS | Phase 2 testing | 🔲 Not Started |

---

## 📁 Suggested Structure Additions

| Path | Purpose |
|------|---------|
| `tests/fixtures/` | Reusable global test objects |
| `rewired/mocks/` | Shared mock data/logic |
| `.github/workflows/ci.yml` | Expanded CI with matrix support and coverage |
| `CONTRIBUTING.md` | Contributor workflow |

---

## 🧠 Strategy Notes

- Start with P2-01, P2-03, and P2-05 to unlock real-world token validation and testing improvements.
- Keep milestone tracking centralized in this file.
- Avoid PR fatigue — group related changes.

---

> Phase 2 is about growing beyond test coverage into real utility, team scalability, and global distribution readiness.
