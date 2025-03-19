## Wazuh RBAC

The Wazuh Role-Based Access Control (RBAC) system and its resources are now managed within the indexer. This template is shared by both `wazuh-internal-users` and `wazuh-custom-users` indices, defining fields for user roles, rules, and policies.

- wazuh-internal-users: Default users and roles built-in with Wazuh.
- wazuh-custom-users: Users and roles created by the admin.

### Fields summary

|     | Field                               | Type      | Description                                       |
| --- | ----------------------------------- | --------- | ------------------------------------------------- |
| \*  | id                                  | keyword   | Unique identifier of the user.                    |
| \*  | name                                | keyword   | The user’s name.                                  |
| \*  | password                            | keyword   | The hashed password of the user.                  |
| \*  | allow_run_as                        | boolean   | Whether the user can run as admin.                |
| \*  | created_at                          | keyword   | Timestamp when the user was created.              |
| \*  | role.name                           | keyword   | The role name.                                    |
| \*  | role.level                          | integer   | The permission level of the role.                 |
| \*  | role.rule.name                      | keyword   | The rule name.                                    |
| \*  | role.rule.body                      | keyword   | The complete body of the rule in JSON.            |
| \*  | role.policy.name                    | keyword   | The Policy name.                                  |
| \*  | role.policy.actions                 | keyword   | Actions allowed by the policy.                    |
| \*  | role.policy.resources               | keyword   | Resources affected by the policy.                 |
| \*  | role.policy.effect                  | keyword   | The effect of the policy (allow/deny).            |
| \*  | role.policy.level                   | integer   | The permission level of the policy.               |

\* Custom field.


### ECS mapping

```yaml
---
- name: policy
  title: Wazuh's User Policy
  description: Policy assigned to a role.
  reusable:
    top_level: false
    expected:
      - { at: role, as: policies }
  level: nested
  fields:
    - name: name
      type: keyword
      level: custom
      description: The Policy name.
    - name: actions
      type: keyword
      level: custom
      description: Actions allowed by the policy.
    - name: resources
      type: keyword
      level: custom
      description: Resources affected by the policy.
    - name: effect
      type: keyword
      level: custom
      description: The effect of the policy (allow/deny).
    - name: level
      type: integer
      level: custom
      description: The permission level of the policy.

```
```yaml
---
- name: role
  title: Wazuh's User Role
  description: List of roles assigned to a user.
  reusable:
    top_level: false
    expected:
      - { at: user, as: roles }
  level: nested
  fields:
    - name: name
      type: keyword
      level: custom
      description: The role name.
    - name: level
      type: integer
      level: custom
      description: The permission level of the role.

```
```yaml
---
- name: rule
  title: Wazuh's User Rule
  description: Rule assigned to a role.
  reusable:
    top_level: false
    expected:
      - { at: role, as: rules }
  level: nested
  fields:
    - name: name
      type: keyword
      level: custom
      description: The rule name.
    - name: body
      type: object
      level: custom
      enabled: true
      description: The complete body of the rule in JSON.

```
```yaml
- name: user
  title: Wazuh User
  short: Users for Wazuh.
  description: >
    Wazuh's users with their roles and policies.
  type: group
  group: 2
  fields:
    - name: id
      type: keyword
      level: custom
      description: Unique identifier of the user.
    - name: name
      type: keyword
      level: custom
      description: The user’s name.
    - name: password
      type: keyword
      level: custom
      description: The hashed password of the user.
    - name: allow_run_as
      type: boolean
      level: custom
      description: Whether the user can run as admin.
    - name: created_at
      type: date
      level: custom
      description: Timestamp when the user was created.

```
