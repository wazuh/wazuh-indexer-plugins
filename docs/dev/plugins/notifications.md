# Wazuh Indexer Notifications Plugin — Development Guide

This document describes the architecture, components, and extension points of the Notifications plugin, which provides multi-channel notification capabilities to the Wazuh Indexer.

---

## Overview

The Notifications plugin handles:

- **Channel Management:** CRUD operations for notification channels (Slack, Email, Chime, Microsoft Teams, Webhooks, SNS, SES).
- **Message Delivery:** Abstracts different communication protocols (SMTP, HTTP, AWS SES/SNS) into a unified transport layer.
- **Test Notifications:** Allows sending test messages to validate channel configuration.
- **Plugin Features:** Exposes dynamic feature discovery so other plugins can query supported notification types.
- **Security Integration:** Integrates with the Wazuh Indexer Security plugin for RBAC-based access control.

---

## Project Structure

The plugin is organized into three Gradle subprojects:

| Subproject | Description |
|---|---|
| `notifications/core-spi` | Service Provider Interface. Defines destination models (`SlackDestination`, `SmtpDestination`, `ChimeDestination`, etc.) and the `NotificationCore` contract. |
| `notifications/core` | Core implementation. Contains HTTP/SMTP/SES/SNS clients, transport providers, and all configurable settings (`PluginSettings`). |
| `notifications/notifications` | Main plugin module. Registers REST handlers, transport actions, index operations, metrics, and security access management. |

---

## Class Hierarchy

### Destination Models (core-spi)

```
BaseDestination
├── SlackDestination
├── ChimeDestination
├── MicrosoftTeamsDestination
├── CustomWebhookDestination
├── WebhookDestination
├── SmtpDestination
├── SesDestination
└── SnsDestination
```

### Transport Layer (core)

```
DestinationTransport (interface)
├── WebhookDestinationTransport      (Slack, Chime, Teams, Webhooks)
├── SmtpDestinationTransport         (SMTP Email)
├── SesDestinationTransport          (AWS SES Email)
└── SnsDestinationTransport          (AWS SNS)
```

### REST Handlers (notifications)

| Handler | Method | URI |
|---|---|---|
| `NotificationConfigRestHandler` | POST | `/_plugins/_notifications/configs` |
| | PUT | `/_plugins/_notifications/configs/{config_id}` |
| | GET | `/_plugins/_notifications/configs/{config_id}` |
| | GET | `/_plugins/_notifications/configs` |
| | DELETE | `/_plugins/_notifications/configs/{config_id}` |
| | DELETE | `/_plugins/_notifications/configs` |
| `NotificationFeaturesRestHandler` | GET | `/_plugins/_notifications/features` |
| `NotificationChannelListRestHandler` | GET | `/_plugins/_notifications/channels` |
| `SendTestMessageRestHandler` | POST | `/_plugins/_notifications/feature/test/{config_id}` |
| `NotificationStatsRestHandler` | GET | `/_plugins/_notifications/_local/stats` |

---

## Setup Environment

### Requirements

- **JDK:** version 11 or 17 (depending on the target Wazuh Indexer version).
- **Gradle:** Use the included `./gradlew` wrapper (no separate install needed).
- **IDE:** IntelliJ IDEA with Kotlin plugin is recommended.

### Clone and Build

```bash
git clone <notifications-repo-url>
cd wazuh-indexer-notifications
./gradlew build
```

The distribution zip will be generated at:
```
notifications/notifications/build/distributions/
```

---

## Build Packages

To create distribution packages:

```bash
# Full build (compile + test + assemble)
./gradlew build

# Assemble only (skip tests)
./gradlew assemble
```

The output zip can be installed on a running Wazuh Indexer using:

```bash
bin/opensearch-plugin install file:///path/to/notifications-<version>.zip
```

---

## Run Tests

### Unit Tests

```bash
./gradlew test
```

### Integration Tests

The integration test suite is located at:
```
notifications/notifications/src/test/kotlin/org/opensearch/integtest/
```

To execute the full integration test suite:

```bash
./gradlew :notifications:notifications:integTest
```

Key integration test classes:

| Test Class | Description |
|---|---|
| `SlackNotificationConfigCrudIT` | Full CRUD lifecycle for Slack channels. |
| `ChimeNotificationConfigCrudIT` | Full CRUD lifecycle for Chime channels. |
| `EmailNotificationConfigCrudIT` | Full CRUD lifecycle for Email channels (SMTP/SES). |
| `MicrosoftTeamsNotificationConfigCrudIT` | Full CRUD lifecycle for Microsoft Teams channels. |
| `WebhookNotificationConfigCrudIT` | Full CRUD lifecycle for custom webhooks. |
| `SnsNotificationConfigCrudIT` | Full CRUD lifecycle for SNS channels. |
| `CreateNotificationConfigIT` | Config creation edge cases and validation. |
| `DeleteNotificationConfigIT` | Config deletion including bulk delete. |
| `QueryNotificationConfigIT` | Filtering, sorting, and pagination queries. |
| `GetPluginFeaturesIT` | Feature discovery endpoint tests. |
| `GetNotificationChannelListIT` | Channel list endpoint tests. |
| `SendTestMessageRestHandlerIT` | Test message delivery flow. |
| `SendTestMessageWithMockServerIT` | Test message with mock destination. |
| `SecurityNotificationIT` | RBAC and access control tests. |
| `MaxHTTPResponseSizeIT` | HTTP response size limit enforcement. |
| `NotificationsBackwardsCompatibilityIT` | Backwards compatibility between versions. |

---

## Notification Flow

The data flow when sending a notification follows this sequence:

```
Monitor/Alerting Plugin
        │
        ▼
Notification Plugin Interface (REST / Transport)
        │
        ▼
Security Plugin (verify permissions)
        │
        ▼
.notifications index (persist notification, status = pending)
        │
        ▼
Transport Action (resolve destination type)
        │
        ├──► WebhookDestinationTransport ──► Slack / Chime / Teams / Custom Webhook
        ├──► SmtpDestinationTransport    ──► External SMTP Server
        ├──► SesDestinationTransport     ──► AWS SES
        └──► SnsDestinationTransport     ──► AWS SNS
                                                  │
                                                  ▼
                                             Recipient
```

1. An internal plugin (Alerting, Reporting, ISM) or a user invokes the Notification plugin via Transport or REST API.
2. The Security plugin verifies the caller's permissions.
3. The notification is persisted in the `.notifications` index with `pending` status.
4. The `DestinationTransportProvider` resolves the correct transport based on the channel type.
5. The transport client delivers the message to the external service.
6. On failure, retries are attempted up to the configured limit.
7. The notification status is updated to `sent` or `failed`.

---

## Extending with a New Destination

To add a new notification destination:

1. **Define the destination model** in `core-spi`:
   - Create a new class extending `BaseDestination` in `notifications/core-spi/src/main/kotlin/.../destination/`.

2. **Implement the transport** in `core`:
   - Create a new class implementing `DestinationTransport` in `notifications/core/src/main/kotlin/.../transport/`.
   - Register it in `DestinationTransportProvider`.

3. **Add the config type** to the `DEFAULT_ALLOWED_CONFIG_TYPES` list in `core/setting/PluginSettings.kt`.

4. **Write tests:** Add integration tests in `notifications/notifications/src/test/kotlin/org/opensearch/integtest/config/`.
