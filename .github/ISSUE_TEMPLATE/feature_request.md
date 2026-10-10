---
name: Feature Request
about: Suggest a new feature or enhancement
title: '[FEATURE] '
labels: enhancement
assignees: ''
---

<!-- A way to get a malicious file past a check that is not already a published
     limit (docs/detection-benchmark.md) is a detection bypass: report it
     privately (SECURITY.md), not here. -->

## Feature Description

A clear and concise description of the feature you'd like to see.

## Problem Statement

What problem does this feature solve? What use case does it enable?

**Example:**
> As a [role], I want [feature] so that [benefit].

## Proposed Solution

Describe how you envision this feature working. For a new or changed check,
say what earns each status: what it inspects for a PASS, the positive evidence
for a FAIL, what makes a LEAD, and when it is NOT_TESTED.

**Example report row or command (if applicable):**
```json
{
  "name": "Your proposed check",
  "looks_for": "What the check inspects",
  "status": "PASS | FAIL | LEAD | NOT_TESTED",
  "notes": "What the row would say"
}
```

## Alternatives Considered

What alternative solutions or features have you considered?

## Additional Context

- Related issues: #
- Similar features in other scanners:
- Workarounds you're currently using:

## Priority

How important is this feature to you?

- [ ] Critical - Blocking my use case
- [ ] High - Would significantly improve my workflow
- [ ] Medium - Nice to have
- [ ] Low - Minor improvement

## Willingness to Contribute

Are you willing to contribute to this feature?

- [ ] Yes, I can submit a PR
- [ ] Yes, I can help test
- [ ] No, but I can provide feedback
- [ ] No, just requesting
