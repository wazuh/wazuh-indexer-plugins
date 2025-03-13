# Set up the development environment

## 1. Git

Install and configure Git (ssh keys, commits and tags signing, user and email).

1. [Set your username](https://docs.github.com/en/get-started/getting-started-with-git/setting-your-username-in-git).
1. [Set your email address](https://docs.github.com/en/account-and-profile/setting-up-and-managing-your-personal-account-on-github/managing-email-preferences/setting-your-commit-email-address).
1. Generate an [SSH key](https://git-scm.com/book/en/v2/Git-on-the-Server-Generating-Your-SSH-Public-Key).
1. Add the public key to your [GitHub account](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/adding-a-new-ssh-key-to-your-github-account) for authentication and signing.
1. [Configure Git to sign commits with your SSH key](https://docs.gitlab.com/ee/user/project/repository/signed_commits/ssh.html#configure-git-to-sign-commits-with-your-ssh-key).

## 2. Repositories

Before  you  start,  you  need  to  properly  configure  your  working repository to have *origin* and *upstream* remotes.

* Clone the `wazuh-indexer` fork

    ```bash
    git clone git@github.com:wazuh-indexer.git
    git remote add upstream git@github.com:opensearch-project/opensearch.git
    ```

* Clone the `wazuh-indexer-reporting` fork

    ```bash
    git clone git@github.com:wazuh/wazuh-indexer-reporting.git
    git remote add upstream git@github.com:opensearch-project/reporting.git
    ```

* Clone the `wazuh-indexer-plugins` repository

    ```bash
    git clone git@github.com:wazuh/wazuh-indexer-plugins.git
    ```

## 3. IntelliJ IDEA

Prepare your IDE:

1. Install IDEA Community Edition as per the [official documentation](https://www.jetbrains.com/help/idea/installation-guide.html).
1. Set a global SDK to Eclipse Temurin following  [this guide](https://www.jetbrains.com/help/idea/sdk.html#add_global_sdk).

> You can find the JDK version to use under the `wazuh-indexer/gradle/libs.versions.toml` file. IntelliJ IDEA includes some JDKs by default. If you need to change it, or if you want to use a different distribution, follow the instructions on the next section.

## 4. JDK (Optional)

We use the Eclipse Temurin JDK. To use a different JDK installed on your machine, use `sudo update-alternatives --config java` to select the JDK of your preference.

Set the **JAVA\_HOME** and **PATH** environment variables by adding these lines to your Shell RC file (`.bashrc`, `.zsrhrc`, …):

```bash
export JAVA_HOME=/usr/lib/jvm/temurin-21-jdk-amd64
export PATH=$PATH:/usr/lib/jvm/temurin-21-jdk-amd64/bin
```

After that, restart your shell or run `source  ~/.zshrc` (or similar) to apply the changes. Finally, check Java is installed correctly by running `java --version`.
