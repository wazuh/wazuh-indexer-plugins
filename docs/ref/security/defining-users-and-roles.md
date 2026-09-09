# Defining users and roles

You can create and manage users and roles through the Wazuh Dashboard UI.

<div class="warning">

Default users and roles cannot be modified. Instead, duplicate them and modify the duplicates.

</div>

## Creating a new user, role, and role mapping via the Wazuh Dashboard

> **Prerequisites**
>
> * You must be logged in as a user with administrative privileges (e.g., `admin`).

Follow these steps:

### 1. Create a role

1. In the Wazuh Dashboard, go to **Index Management** -> **Security** -> **Roles**.
2. Click **Create role**.
3. Enter a **Role name** (e.g., `custom-read-write`).
4. Under **Cluster permissions**, select permissions if needed.
5. Under **Index permissions**:
    * **Index**: e.g., `wazuh-*`
    * **Index permissions**: choose appropriate actions such as:
        * `read` (to allow read access)
        * `index` (to allow write access)
    * Optionally, configure [**Document-level security (DLS)**](https://docs.opensearch.org/3.6/security/access-control/index/) or [**Field-level security (FLS)**](https://docs.opensearch.org/3.6/security/access-control/field-level-security/).
6. Click **Create** to save the role.

<div class="warning">

**Do not map users to the built-in `kibana_user` role.**

Its name suggests it is what a dashboard user needs, and the upstream OpenSearch documentation recommends it for that purpose. It grants `delete`, `index` and `manage` over the `.kibana*` indices, which is where the Wazuh Dashboard stores its saved objects: the index patterns, visualizations and dashboards Wazuh ships.

Wazuh Indexer disables Dashboard multi-tenancy, so there is no per-user space for those writes to land in. A user holding the role can delete any shipped index pattern — immediately, permanently, and with no undo — or edit its title so that every visualization built on it silently reads from different indices, with nothing in the interface indicating that it changed or who changed it.

No default Wazuh user holds this role: the interactive ones have read-only access to `.kibana*`, and saved objects are managed by `admin`. Custom roles should follow the same rule — grant the permissions the user needs on the Wazuh index patterns and leave `.kibana*` alone.

</div>

### 2. Create a user

1. In the Wazuh Dashboard, go to **Index Management** -> **Security** -> **Internal users**.
2. Click **Create internal user**.
3. Fill in the following:
    * **Username** (e.g., `new-user`)
    * **Password** (enter and confirm)
    * **Description** (optional)
4. Click **Create** to create the user.

### 3. Verify role mapping

When you assign a role to a user during creation, the mapping is created automatically. To review or edit:

1. In **Security**, go to **Roles**.
2. Find and click your role (`custom-read-write`).
3. Go to **Mapped users**
4. Click **Map users**.
5. Fill in the following:
   * **Users** (e.g., `new-user`).
   * **Backend roles** (optional).
6. Click **Map** to save the mapping.

### 4. Test access

After creating the user and role:

1. Log out from the Dashboard.
2. Log in with the new user's credentials.
3. Navigate to **Index Management** -> **Dev Tools**.
4. Run a query  to test access, such as:
   ```console
   GET /wazuh-*/_search
   ```

---

## Additional resources

* [OpenSearch Security Plugin - User-Roles Management](https://docs.opensearch.org/3.6/security/access-control/users-roles/)

