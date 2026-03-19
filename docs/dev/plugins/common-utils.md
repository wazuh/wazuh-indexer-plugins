
# Wazuh Indexer Common Utils — Development Guide

This document describes the architecture, components, and development process for the **Wazuh Indexer Common Utils** library, which provides foundational Java components for Wazuh Indexer plugins.

---

## Overview

The **Wazuh Indexer Common Utils** library is a core dependency designed to reduce code duplication and ensure consistent security practices across the Wazuh Indexer ecosystem. It is a fork of the OpenSearch `common-utils` project, tailored for Wazuh.

The library handles:
- **Secure Connectivity:** Simplifies the creation of secure REST clients.
- **Security Injection:** Facilitates running background tasks with specific user roles.
- **Testing Utilities:** Provides specialized classes for integration testing with security enabled.
- **Shared Transport:** Standardizes request/response models for inter-plugin communication.

---

## Project Structure

This repository is organized as a centralized library of reusable components:

| Component | Description |
|---|---|
| **`SecureRestClientBuilder`** | Methods to create secure low-level and high-level REST clients for communication with the Indexer or other APIs. |
| **`InjectSecurity`** | Utilities to inject user contexts or roles, essential for secure background job execution. |
| **`IntegTestsWithSecurity`** | Framework-specific methods to programmatically create users and roles during integration test suites. |
| **Shared Transport** | Common action, request, and response classes used for transport-layer calls between different plugins. |
| **Common Functionality** | Centralized logic used across multiple Wazuh Indexer plugins to maintain DRY (Don't Repeat Yourself) principles. |

---

## Class Hierarchy & Key Modules

### Security & Client Utilities

```
Common Utils
├── SecureRestClientBuilder (REST Client Creation)
├── InjectSecurity         (Security Context Injection)
└── IntegTestsWithSecurity (Testing Framework)
```

### Communication Layer
- **Shared Transport Classes**: Base classes for plugin-to-plugin communication.
- **Common Logic**: Utility methods for data validation, parsing, and Indexer-specific operations.

---

## Setup Environment

### Requirements

- **JDK:** Version 21 (Minimum).
- **Environment Variable:** `JAVA_HOME` must point to your JDK 21 installation (e.g., `JAVA_HOME=/usr/lib/jvm/jdk-21`).
- **Gradle:** Use the included `./gradlew` wrapper.
- **IDE:** IntelliJ IDEA is recommended.

### Clone and Build

```bash
git clone <wazuh-indexer-common-utils-repo-url>
cd wazuh-indexer-common-utils
./gradlew build
```

---

## Build and Deployment

To compile the library and make it available for other plugins locally:

```bash
# Clean previous builds
./gradlew clean

# Full build and compilation
./gradlew build

# Publish to local Maven repository (~/.m2/repository)
./gradlew publishToMavenLocal
```

### Using IntelliJ IDEA
1. Launch IntelliJ IDEA.
2. Select **Import Project** (or **Open**).
3. Select the `settings.gradle` file in the root directory.

---

## Run Tests

The library includes unit and integration tests to ensure the reliability of common components.

### Unit Tests
```bash
./gradlew test
```

### Integration Tests
Integration tests often utilize the `IntegTestsWithSecurity` classes to simulate real-world plugin environments with RBAC enabled.

| Test Category | Description |
|---|---|
| **Security Injection Tests** | Validates that roles are correctly applied to background threads. |
| **REST Client Tests** | Ensures `SecureRestClientBuilder` correctly handles TLS and authentication. |
| **Transport Tests** | Verifies serialization/deserialization of shared transport objects. |

---

## Contribution Flow

To contribute changes to the Wazuh Indexer Common Utils:

1. **Fork and Clone:** Fork the repository on GitHub and clone it locally.
2. **Implement Changes:** Ensure code follows the established patterns and includes tests.
3. **Verify:** Run `./gradlew build` to ensure all checks pass.
4. **Submit:** Follow the [CONTRIBUTING.md](./CONTRIBUTING.md) guidelines and open a Pull Request.

