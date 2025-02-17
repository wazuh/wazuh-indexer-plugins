# Packages generation

## Definitions
- Slim package: package containing the Indexer alone.
- Final package: package containing  the Indexer,  plugins and configurations.

## List of changes
Check this [issue](https://github.com/wazuh/wazuh-indexer/issues/60).

## Supported operating systems
Wazuh indexer should work on many Linux distributions, but we only test a handful. The following table lists the operating system versions that we currently support.

<table>
  <tr>
    <td>Amazon Linux 2</td>
    <td>CentOS 7, 8</td>
  </tr>
  <tr>
    <td>Red Hat Enterprise Linux 7, 8, 9</td>
    <td>Ubuntu 16.04, 18.04, 20.04, 22.04</td>
  </tr>
</table>

The list of supported systems must always match these in the [documentation](https://documentation.wazuh.com/current/installation-guide/wazuh-indexer/index.html). The indexer team is also responsible for maintaining it up to date. 

We aim to support as many operating systems as [OpenSearch](https://opensearch.org/docs/2.11/install-and-configure/install-opensearch/index/#operating-system-compatibility) does. For 4.9.0 and above, we want to support the operating system versions and architectures included in the [Central Components sheet](https://docs.google.com/spreadsheets/d/1Zs9vUtpsw8jj3Sggr4fC8TAQpYA1SAiwplF3H595nQQ/edit#gid=949689823).

| Name          | Version     | Architecture |
|---------------|-------------|--------------|
| Red Hat       | 7, 8, 9     | x86_64       |
| Ubuntu        | 22.04, 24.04| x86_64       |
| Amazon Linux  | 2, 2023     | x86_64       |
| CentOS        | 7, 8        | x86_64       |

## Introduction

The packages building process consists of 2 steps:

- Build: compiles the Java code and bundles it into a package.
- Assemble: uses the package from the previous step and complements it with plugins and production-ready configuration files.

We usually build the packages using a [GitHub Workflow](https://github.com/wazuh/wazuh-indexer/blob/4.9.0/.github/workflows/build.yml), which automates the whole process. However, the process is designed to be independent enough for maximum portability. GitHub Actions provides the infrastructure, while the building logic is self-contained in the application code (Gradle) and the project repository (**bash scripts**).

As the process is divided into several steps, and they share contents with each other (the packages), **a solid naming convention is key**. For this reason, the names of the packages are generated automatically by the baptizer.sh script, which will generate the expected package name depending on the parameters provided. Running this script is innocuous, so feel free to play around with it to get familiar with the naming convention. It’s worth mentioning that the naming convention depends on the package type:

- Development package
```
any ~~ <SubsystemName>_<VersionNumber>-<Revision>_<Architecture>_<GitRef>.<PackageType>
```

- Release (stage) package
```
deb ~~ <SubsystemName>_<VersionNumber>-<Revision>_<Architecture>.<PackageType>
rpm ~~ <SubsystemName>_<VersionNumber>-<Revision>.<Architecture>.<PackageType>
```

Each section includes instructions to generate packages locally or using Docker.

## Requirements
- The VERSION file must contain the version of Wazuh as a single line.

## GitHub Workflow
1. Go to the Actions section of the wazuh-indexer repository.
1. Select the [“Build packages (on demand)”](https://github.com/wazuh/wazuh-indexer/actions/workflows/build.yml) workflow.
1. Fill the form and click on “Run workflow”.

## Docker
Refer to the [documentation in the repository](https://github.com/wazuh/wazuh-indexer/blob/master/build-scripts/README.md).

## Scripts reference
Refer to the [REFERENCE.md](https://github.com/wazuh/wazuh-indexer/blob/master/build-scripts/REFERENCE.md) in the repository.


TL;DR: OpenSearch has a special repository to build and test all their package, similar to our <a href="https://github.com/wazuh/wazuh-packages">wazuh-packages</a> repository, with the difference that all their workflows are fully automated. In order to achieve this, their repos require a certain folder structure and set of files. <a href="https://github.com/opensearch-project/opensearch-build/tree/2.11.0/src/build_workflow#custom-build-scripts">The scripts folder and the build.sh script inside of it</a> is the most notable example, and the most important for our use case.


The packages are sent to:
- distribution/$TYPE/$TARGET/build/distributions/$ARTIFACT_BUILD_NAME
- "${OUTPUT}"/dist/$ARTIFACT_BUILD_NAME

where,
- TYPE=archives|packages
- ARTIFACT_BUILD_NAME=wazuh-indexer-min.*$SUFFIX.$DISTTRIBUTION"

As output, the folder artifacts will be created, with 3 folders inside of it:
- **core-plugins**: compiled plugins inside the plugins folder at root level. These plugins are not included in the package, but manually installed.
- **dist**: all the packages will be store here: tar.gz, rpm, deb, …
- **maven**: maven local repository. Contains the compiled Java jars for each of the projects.

## Testing
We smoke test the packages using the [GitHub Actions Workflows](https://github.com/wazuh/wazuh-indexer/blob/4.9.0/.github/workflows/build.yml). These tests consist on installing the packages on a supported operating system. DEB packages are installed in the “Ubuntu 24.04” runner executing the workflow, while RPM packages are installed in a Red Hat 9 Docker container, as there is no RPM compatible runner available in GitHub Actions.

More extensive testing is performed by the QA team. Also, through E2E testing.

As a last note, there is also a **Vagrantfile** and **testing scripts** in the [repository](https://github.com/wazuh/wazuh-indexer/tree/master/test-tools) to test packaging. Refer to the README.md for more information.

## Configuration file handling
Upon upgrade, if any configuration file has been changed since it was first installed, the existing version takes precedence over the maintainer’s version (the one shipped in the new package). This is made so the user modifications to these files are not overwritten. For RPM packages, the files are suffixed after **rpmnew**. For Debian packages, **dpkg** asks the user for manual conflict resolution.
- [Debian Policy Manual - Configuration file handling](https://www.debian.org/doc/debian-policy/ap-pkg-conffiles.html#:~:text=If%20neither%20the,the%20differences%20themselves.)
- [Maximum RPM: Chapter 13. Inside the Spec File](http://ftp.rpm.org/max-rpm/s1-rpm-inside-files-list-directives.html)
- [RPM Spec file format](https://rpm-software-management.github.io/rpm/manual/spec.html)
