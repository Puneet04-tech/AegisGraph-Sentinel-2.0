# Contributor Handbook

Welcome to AegisGraph Sentinel 2.0.

This handbook helps contributors understand the project structure, workflow, and contribution standards.

---

# Repository Structure

```text
src/
├── api/
├── models/
├── features/
├── inference/
├── training/
├── utils/

tests/

config/

docs/
```

---

# Branch Naming Convention

Use descriptive branch names.

Examples:

```text
feature/add-risk-module
fix/api-validation
docs/system-architecture
```

---

# Commit Message Convention

Use Conventional Commits.

Examples:

```text
feat: add risk scoring module

fix: resolve transaction validation bug

docs: update architecture guide

test: add velocity calculator tests
```

---

# Development Workflow

1. Fork repository
2. Clone fork
3. Create branch
4. Make changes
5. Test locally
6. Commit
7. Push
8. Create Pull Request

---

# Documentation Contributions

Good documentation contributions include:

- Architecture guides
- API examples
- Testing instructions
- Setup tutorials
- Developer onboarding guides

---

# Code Contributions

Before submitting code:

- Follow project style
- Write meaningful comments
- Add tests when possible
- Verify functionality

---

# Pull Request Checklist

Before opening a PR:

- Code builds successfully
- Documentation updated
- Tests pass
- Commit messages follow standards
- No unnecessary files included

---

# Common Mistakes

Avoid:

- Large unrelated changes
- Hardcoded secrets
- Unused dependencies
- Missing documentation
- Missing tests

---

# Recommended Learning Path

New contributors should explore:

1. README.md
2. CONTRIBUTING.md
3. System Architecture Guide
4. API Cookbook
5. Source Code Structure

This progression provides a complete understanding of the project.