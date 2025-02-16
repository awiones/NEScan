---
name: Bug Report
about: Report issues or unexpected behavior in the project.
title: ''
labels: ''
assignees: ''

---

name: Bug Report
description: Report an issue with the project
title: "[BUG] Your issue title here"
labels: ["bug"]
assignees: []

body:
  - type: markdown
    attributes:
      value: |
        ## Bug Description
        Clearly describe the problem.

  - type: textarea
    attributes:
      label: Steps to Reproduce
      description: Provide detailed steps to reproduce the issue.

  - type: textarea
    attributes:
      label: Expected Behavior
      description: Describe what you expected to happen.

  - type: textarea
    attributes:
      label: Actual Behavior
      description: Describe what actually happened.

  - type: input
    attributes:
      label: Environment
      description: Specify the environment details (e.g., OS, browser, version).

  - type: dropdown
    attributes:
      label: Severity
      description: Choose the severity level of the bug.
      options:
        - Low
        - Medium
        - High
