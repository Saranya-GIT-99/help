# OPA Rego + Ansible Governance Control Documentation

## Overview

This document explains how Rego policies and an Ansible playbook are used together to enforce governance and security controls in your automation workflows. The design ensures production-level access is validated, and risky operations are blocked through policy.

---

## Rego Policies Summary

### 1. Package Control Policy

**File:** `package main`

```rego
deny_unapproved_version contains msg if {
  package_name := input["ansible.builtin.package"].name
  package_name in ["telnet", "wireshark"]
  msg := sprintf("One of the package is not allowed - %v", [package_name])
}
```

**Purpose:** Disallow installation of unapproved packages.

---

### 2. Ansible Module Restriction Policy

**File:** `package ansible.module`

```rego
deny = msg {
  some key, _ in input[_]
  key == "shutdown"
  msg := sprintf("One of the Ansible module is not allowed %v", [key])
}
```

**Purpose:** Blocks usage of modules that perform shutdowns.

---

### 3. Shell Command Restriction Policy

**File:** `package ansible.cmd`

```rego
deny_unapproved_version contains msg if {
  cmd_name := input["command"]
  cmd_name in ["rm -rf /*", "rm -rf /", "shutdown"]
  msg := sprintf("One of the cmd is not allowed - %v", [cmd_name])
}
```

**Purpose:** Prevent execution of destructive commands.

---

## Ansible Playbook Workflow Summary

### Step 1: Fetch Job Template Information

* Uses Tower API to get the job template metadata.

### Step 2: Extract Last Job Info

* Pulls the last job ID and status.

### Step 3: Capture Job Context

* Launch type, credentials (especially SSH kind), and inventory name are extracted.

### Step 4: Determine User and CR Number

* If launched by a Western Union user, use their email.
* Otherwise, use external user and set CR number.

### Step 5: Launch SNOW Validation Job

* Triggered only for **production-like** credentials or inventory.

### Step 6: Monitor Job Status

* Waits for validation job to complete.
* Fails the pipeline if SNOW job fails.

### Step 7: Run Local Policy Validation

* Uses `conftest` to validate policies against Ansible roles before promotion.

---

## Security Enforcement Logic

| Component             | Control                                               |
| --------------------- | ----------------------------------------------------- |
| Rego (package policy) | Blocks disallowed packages                            |
| Rego (module policy)  | Blocks shutdown module                                |
| Rego (command policy) | Blocks destructive shell commands                     |
| Ansible Job Filter    | Restricts SNOW validation to production contexts only |
| `conftest`            | Enforces OPA policies during CI runs                  |

---

## Suggestions for Improvement

* Add output logging of `conftest` results.
* Store job metadata and validation history.
* Introduce additional Rego policies for user groups, sudo commands, etc.
* Automate this validation in GitLab/GitHub CI using conftest plugins.

---

## References

* [OPA Rego Language](https://www.openpolicyagent.org/docs/latest/policy-language/)
* [Ansible Tower API Docs](https://docs.ansible.com/automation-controller/latest/html/controllerapi/index.html)
* [Conftest](https://www.conftest.dev/)
