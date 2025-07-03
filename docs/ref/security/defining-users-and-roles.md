# Defining Users and Roles

You can create and manage users and roles through the Wazuh Dashboard UI.

## Creating a New User, Role, and Role Mapping via the Wazuh Dashboard

> **Prerequisites**
>
> * You must be logged in as a user with administrative privileges (e.g., `admin`).

Follow these steps:

### 1. Create a Role

1. In the Wazuh Dashboard, go to **Index Management** -> **Security** -> **Roles**.
2. Click **Create role**.
3. Enter a **Role name** (e.g., `custom-read-write`).
4. Under **Cluster permissions**, select permissions if needed.
5. Under **Index permissions**:
    * **Index**: e.g., `wazuh-*`
    * **Index permissions**: choose appropriate actions such as:
        * `read` (to allow read access)
        * `index` (to allow write access)
    * Optionally, configure [**Document-level security (DLS)**](https://docs.opensearch.org/docs/latest/security/access-control/index/) or [**Field-level security (FLS)**](https://docs.opensearch.org/docs/latest/security/access-control/field-level-security/).
6. Click **Create** to save the role.

### 2. Create a User

1. In the Wazuh Dashboard, go to **Index Management** -> **Security** -> **Internal users**.
2. Click **Create internal user**.
3. Fill in the following:
    * **Username** (e.g., `new-user`)
    * **Password** (enter and confirm)
    * **Description** (optional)
4. Click **Create** to create the user.

### 3. Verify Role Mapping

When you assign a role to a user during creation, the mapping is created automatically. To review or edit:

1. In **Security**, go to **Roles**.
2. Find and click your role (`custom-read-write`).
3. Go to **Mapped users**
4. Click **Map users**.
5. Fill in the following:
   * **Users** (e.g., `new-user`).
   * **Backend roles** (optional).
6. Click **Map** to save the mapping.

### 4. Test Access

After creating the user and role:

1. Log out from the Dashboard.
2. Log in with the new user's credentials.
3. Navigate to **Index Management** -> **Dev Tools**.
4. Run a query  to test access, such as:
   ```console
   GET /wazuh-*/_search
   ```

---

## Additional Resources

* [OpenSearch Security Plugin - User Management](https://opensearch.org/docs/latest/security/access-control/users/)
* [OpenSearch Security Plugin - Roles](https://opensearch.org/docs/latest/security/access-control/roles/)

