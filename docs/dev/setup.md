# Environment Setup Guide


## 1. Git 

Install and configure Git (ssh keys, commits and tags signing, user and email). 

1. [Set your username. ](https://docs.github.com/en/get-started/getting-started-with-git/setting-your-username-in-git)
1. [Set your email address.  ](https://docs.github.com/en/account-and-profile/setting-up-and-managing-your-personal-account-on-github/managing-email-preferences/setting-your-commit-email-address)
1. Generate an [SSH key. ](https://git-scm.com/book/en/v2/Git-on-the-Server-Generating-Your-SSH-Public-Key)
1. Add the public key to your [GitHub account ](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/adding-a-new-ssh-key-to-your-github-account)for authentication and signing. 
1. [Configure Git to sign commits with your SSH key ](https://docs.gitlab.com/ee/user/project/repository/signed_commits/ssh.html#configure-git-to-sign-commits-with-your-ssh-key)

## 2. Repositories

Before  you  start,  you  need  to  properly  configure  your  working repository to have *origin* and *upstream* remotes.

### Clone the main fork
```bash
git clone git@github.com:wazuh/-indexer.git 
```
### Add the upstream 
```bash
git remote add upstream git@github.com:opensearch-project/opensearch.git
```
### Clone the plugins 
```bash
git clone git@github.com:wazuh/wazuh-indexer-plugins.git
```
### Clone the reporting plugin fork
```bash
git clone git@github.com:wazuh/wazuh-indexer-reporting.git
```
### Add the upstream 
```bash
git remote add upstream git@github.com:opensearch-project/reporting.git
```

## 3. IntelliJ IDEA 

Prepare your IDE: 

1. Install IDEA Community Edition as per the [official documentation](https://www.jetbrains.com/help/idea/installation-guide.html).
1. Set a global SDK to Eclipse Temurin following  [this guide](https://www.jetbrains.com/help/idea/sdk.html#add_global_sdk).


## 4. JDK (Optional)

Install Eclipse Temurin as per the official documentation. The version to install must match the [JDK version](https://github.com/opensearch-project/OpenSearch/blob/aaa555453f4713d652b52436874e11ba258d8f03/buildSrc/version.properties#L5C15-L5C23) used by the Indexer. To use different JDK, choose the one to use by default using `sudo update-alternatives --config java`.


Set **JAVA\_HOME** and **PATH** environment variables by adding these lines to your Shell RC file (.bashrc, .zsrhrc, …): 
```bash
export JAVA_HOME=/usr/lib/jvm/temurin-21-jdk-amd64
export PATH=$PATH:/usr/lib/jvm/temurin-21-jdk-amd64/bin
```
- Restart your shell or run `source  ~/.zshrc` (or similar) to apply the changes. 
- Check Java is installed correctly running `java --version`. 
