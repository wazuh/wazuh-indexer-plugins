# Set up the Development Environment

## 1. Git

Install and configure Git (SSH keys, commits and tags signing, user and email).

1. [Set your username](https://docs.github.com/en/get-started/getting-started-with-git/setting-your-username-in-git).
2. [Set your email address](https://docs.github.com/en/account-and-profile/setting-up-and-managing-your-personal-account-on-github/managing-email-preferences/setting-your-commit-email-address).
3. Generate an [SSH key](https://git-scm.com/book/en/v2/Git-on-the-Server-Generating-Your-SSH-Public-Key).
4. Add the public key to your [GitHub account](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/adding-a-new-ssh-key-to-your-github-account) for authentication and signing.
5. [Configure Git to sign commits with your SSH key](https://docs.gitlab.com/ee/user/project/repository/signed_commits/ssh.html#configure-git-to-sign-commits-with-your-ssh-key).

## 2. Repositories

Before you start, properly configure your working repositories with *origin* and *upstream* remotes.

- Clone the `wazuh-indexer` fork:

    ```bash
    git clone git@github.com:wazuh-indexer.git
    git remote add upstream git@github.com:opensearch-project/opensearch.git
    ```

- Clone the `wazuh-indexer-reporting` fork:

    ```bash
    git clone git@github.com:wazuh/wazuh-indexer-reporting.git
    git remote add upstream git@github.com:opensearch-project/reporting.git
    ```

- Clone the `wazuh-indexer-plugins` repository:

    ```bash
    git clone git@github.com:wazuh/wazuh-indexer-plugins.git
    ```

## 3. IntelliJ IDEA

Prepare your IDE:

1. Install IDEA Community Edition as per the [official documentation](https://www.jetbrains.com/help/idea/installation-guide.html).
2. Set a global SDK to Eclipse Temurin following [this guide](https://www.jetbrains.com/help/idea/sdk.html#add_global_sdk).

> You can find the JDK version to use under the `wazuh-indexer/gradle/libs.versions.toml` file. IntelliJ IDEA includes some JDKs by default. If you need to change it, or if you want to use a different distribution, follow the instructions in the next section.

## 4. JDK

The project currently requires **JDK 24** (Eclipse Temurin). Verify your version:

```bash
java --version
```

If you need to install or switch JDK versions, use `sudo update-alternatives --config java` to select the JDK of your preference.

Set the **JAVA_HOME** and **PATH** environment variables by adding these lines to your shell RC file (`.bashrc`, `.zshrc`, etc.):

```bash
export JAVA_HOME=/usr/lib/jvm/temurin-24-jdk-amd64
export PATH=$PATH:/usr/lib/jvm/temurin-24-jdk-amd64/bin
```

After that, restart your shell or run `source ~/.zshrc` (or similar) to apply the changes. Verify with `java --version`.

> **Tip:** [SDKMAN](https://sdkman.io/) is a convenient tool for managing multiple JDK versions:
> ```bash
> sdk install java 24-tem
> sdk use java 24-tem
> ```

## 5. Docker (Optional)

Docker is useful for running integration tests and local test environments. Install Docker Engine following the [official instructions](https://docs.docker.com/engine/install/).

Verify the installation:

```bash
docker --version
docker run hello-world
```

## 6. Test Cluster (Optional)

The repository includes a Vagrant-based test cluster at [`tools/test-cluster/`](https://github.com/wazuh/wazuh-indexer-plugins/tree/main/tools/test-cluster) for end-to-end testing against a real Wazuh Indexer instance.

Prerequisites:
- [Vagrant](https://www.vagrantup.com/downloads)
- [VirtualBox](https://www.virtualbox.org/wiki/Downloads) or another supported provider

Refer to the `tools/test-cluster/README.md` for provisioning and usage instructions.

## 7. Verify the Setup

After completing the setup, verify everything works:

```bash
cd wazuh-indexer-plugins
./gradlew :wazuh-indexer-content-manager:compileJava
```

If compilation succeeds, your environment is ready. See [Build from Sources](build-sources.md) for more build commands.
