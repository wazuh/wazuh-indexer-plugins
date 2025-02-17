# Content Manager

The Content Manager plugin is a new plugin for Wazuh 5.0.0.

Main issue: [https://github.com/wazuh/internal-devel-requests/issues/1459](https://github.com/wazuh/internal-devel-requests/issues/1459)
- New index for Wazuh Content (CVE, ruleset, ...).
- New index for custom user content (user ruleset).
- Automatic process for conflicts resolution. Merging user ruleset + wazuh ruleset = active ruleset.
- The Engine pulls the content from the indices. Notified via commands.

**Content Manager responsibilities**
1. Download ruleset from CTI.
1. Generate the active ruleset.
1. Generate a command for the Command Manager to notify the Wazuh Servers about new content available to download.
