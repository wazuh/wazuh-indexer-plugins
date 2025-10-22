# Wazuh Common Schema

The Wazuh Common Schema (WCS) is a standardized structure for organizing and categorizing security event data collected by Wazuh. It is designed to facilitate data analysis, correlation, and reporting across different data sources and types.

### Categorization

The Wazuh Common Schema categorizes events into several key areas to streamline data management and analysis.

#### Access Management

None yet.

#### Applications and Web Servers

| Integration Name                         | Subcategory | Category     |
| ---------------------------------------- | ----------- | ------------ |
| Apache integration                       | Apache      | Applications |
| NGINX integration                        | -           | Applications |
| IIS integration                          | -           | Applications |
| Apache Tomcat integration                | Apache      | Applications |
| WebSphere Application Server integration | -           | Applications |
| Oracle WebLogic Server integration       | -           | Applications |
| Spring Boot integration                  | -           | Applications |
| squid                                    | -           | Applications |

#### Cloud Services

| Integration Name     | Subcategory | Category       |
| -------------------- | ----------- | -------------- |
| Amazon Security Lake | AWS         | Cloud Services |
| AWS                  | AWS         | Cloud Services |
| AWS Bedrock          | AWS         | Cloud Services |
| AWS Logs             | AWS         | Cloud Services |
| AWS Fargate          | AWS         | Cloud Services |
| AWS Firehose         | AWS         | Cloud Services |
| Azure                | Azure       | Cloud Services |
| Azure Blob Storage   | Azure       | Cloud Services |
| Azure App Service    | Azure       | Cloud Services |
| Azure Functions      | Azure       | Cloud Services |
| Azure Metrics        | Azure       | Cloud Services |
| Azure OpenAI         | Azure       | Cloud Services |
| Cisco Umbrella       | Cisco       | Cloud Services |
| GCP                  | Google      | Cloud Services |
| Google SCC           | Google      | Cloud Services |

#### Network Activity

| Integration Name    | Subcategory | Category         |
| ------------------- | ----------- | ---------------- |
| iptables            | -           | Network Activity |
| Cisco ASA           | Cisco       | Network Activity |
| Cisco IOS           | Cisco       | Network Activity |
| Cisco Meraki        | Cisco       | Network Activity |
| Cisco Aironet       | Cisco       | Network Activity |
| Fortinet Fortigate  | Fortinet    | Network Activity |
| CheckPoint          | -           | Network Activity |
| SonicWall           | -           | Network Activity |
| F5 BIG-IP           | -           | Network Activity |
| pfSense             | -           | Network Activity |
| Fortinet Fortiproxy | Fortinet    | Network Activity |

#### Security 

| Integration Name | Subcategory | Category |
| ---------------- | ----------- | -------- |
| Snort            | -           | Security |
| Suricata         | -           | Security |
| ModSecurity      | -           | Security |
| Zeek             | -           | Security |

#### System Activity

| Integration Name        | Subcategory | Category        |
| ----------------------- | ----------- | --------------- |
| Auditd                  | Linux       | System Activity |
| Sysmon Linux            | Linux       | System Activity |
| Windows                 | Windows     | System Activity |
| Windows DHCP            | Windows     | System Activity |
| Windows DNS server      | Windows     | System Activity |
| Windows Exchange server | Windows     | System Activity |
| ULS                     | macOS       | System Activity |

#### Other

None yet.

### Indices

```
wazuh-events-5.x-access-management-000001
wazuh-events-5.x-applications-000001
wazuh-events-5.x-cloud-services-000001
wazuh-events-5.x-network-activity-000001
wazuh-events-5.x-security-000001
wazuh-events-5.x-system-activity-000001
wazuh-events-5.x-other-000001
```

### Aliases

```
wazuh-events-5.x-access-management
wazuh-events-5.x-applications
wazuh-events-5.x-cloud-services
wazuh-events-5.x-network-activity
wazuh-events-5.x-security
wazuh-events-5.x-system-activity
wazuh-events-5.x-other
```