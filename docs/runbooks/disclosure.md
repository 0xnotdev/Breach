# Disclosure boundary

Breach is a private validation system, not an automated disclosure agent. It must not contact maintainers, create issues, send payloads, verify credentials, probe a deployment, publish findings, or open remediation pull requests.

An operator may mark a finding CONFIRMED, FALSE_POSITIVE, or UNCERTAIN using semantic evidence and limitations. Any later disclosure is a separate, explicitly authorized human process. Reconfirm repository ownership and current revision outside this system, minimize shared metadata, exclude raw secrets/source, and follow the repository's security policy and applicable coordinated-disclosure rules.

Static exploitability is not proof of runtime compromise. Every communicated result must preserve the labels: no runtime verification, no active testing, no deployment confirmation, first observed committed HEAD only, and bounded modeled coverage.
