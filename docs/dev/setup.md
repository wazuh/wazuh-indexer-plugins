# Set up the Development Environment

## 1. Git

Install and configure Git (SSH keys, commits and tags signing, user and email).

1. [Set your username](https://docs.github.com/en/get-started/getting-started-with-git/setting-your-username-in-git).
2. [Set your email address](https://docs.github.com/en/account-and-profile/setting-up-and-managing-your-personal-account-on-github/managing-email-preferences/setting-your-commit-email-address).
3. Generate an [SSH key](https://git-scm.com/book/en/v2/Git-on-the-Server-Generating-Your-SSH-Public-Key).
4. Add the public key to your [GitHub account](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/adding-a-new-ssh-key-to-your-github-account) for authentication and signing.
5. [Configure Git to sign commits with your SSH key](https://docs.gitlab.com/ee/user/project/repository/signed_commits/ssh.html#configure-git-to-sign-commits-with-your-ssh-key).

## 2. Repositories

Clone the Wazuh Indexer repositories (use SSH). Before you start, you need to properly configure your working repositories to have *origin* and *upstream* remotes.

```bash
mkdir -p ~/wazuh && cd ~/wazuh

# Plugins (no upstream fork)
git clone git@github.com:wazuh/wazuh-indexer-plugins.git

# Indexer core (forked from OpenSearch)
git clone git@github.com:wazuh/wazuh-indexer.git
cd wazuh-indexer
git remote add upstream git@github.com:opensearch-project/opensearch.git
cd ..

# Reporting plugin (forked from OpenSearch)
git clone git@github.com:wazuh/wazuh-indexer-reporting.git
cd wazuh-indexer-reporting
git remote add upstream git@github.com:opensearch-project/reporting.git
cd ..

# Security Analytics (forked from OpenSearch)
git clone git@github.com:wazuh/wazuh-indexer-security-analytics.git
cd wazuh-indexer-security-analytics
git remote add upstream git@github.com:opensearch-project/security-analytics.git
cd ..
```

## 3. Vagrant

Install Vagrant with the Libvirt provider following the [official guide](https://developer.hashicorp.com/vagrant/docs/providers/libvirt).

Then install the Vagrant SCP plugin:

```bash
vagrant plugin install vagrant-scp
```

## 4. IntelliJ IDEA

Prepare your IDE:

1. Install IDEA Community Edition as per the [official documentation](https://www.jetbrains.com/help/idea/installation-guide.html).
2. Set a global SDK to Eclipse Temurin following [this guide](https://www.jetbrains.com/help/idea/sdk.html#add_global_sdk).

> You can find the JDK version to use under the `wazuh-indexer/gradle/libs.versions.toml` file. IntelliJ IDEA includes some JDKs by default. If you need to change it, or if you want to use a different distribution, follow the instructions in the next section.

## 5. Set up Java

When you open a Java project for the first time, IntelliJ will ask you to install the appropriate JDK for the project.

Using IDEA, install a JDK following [this guide](https://www.jetbrains.com/help/idea/sdk.html#add_global_sdk). The version to install must match the JDK version used by the Indexer (check `wazuh-indexer/gradle/libs.versions.toml`).

Once the JDK is installed, configure it as the default system-wide Java installation using `update-alternatives`:

```bash
sudo update-alternatives --install /usr/bin/java java /home/$USER/.jdks/temurin-21.0.9/bin/java 0
```

Check Java is correctly configured:

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

## 6. Docker (Optional)

Docker is useful for running integration tests and local test environments. Install Docker Engine following the [official instructions](https://docs.docker.com/engine/install/).

Verify the installation:

```bash
docker --version
docker run hello-world
```

## 7. Test Cluster (Optional)

The repository includes a Vagrant-based test cluster at [`tools/test-cluster/`](https://github.com/wazuh/wazuh-indexer-plugins/tree/main/tools/test-cluster) for end-to-end testing against a real Wazuh Indexer instance.

Prerequisites:
- [Vagrant](https://www.vagrantup.com/downloads)
- [VirtualBox](https://www.virtualbox.org/wiki/Downloads) or another supported provider

Refer to the `tools/test-cluster/README.md` for provisioning and usage instructions.

## 8. Verify the Setup

After completing the setup, verify everything works:

```bash
cd wazuh-indexer-plugins
./gradlew :wazuh-indexer-content-manager:compileJava
```

If compilation succeeds, your environment is ready. See [Build from Sources](build-sources.md) for more build commands.
