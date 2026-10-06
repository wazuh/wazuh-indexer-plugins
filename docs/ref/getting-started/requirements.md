## Requirements

### Supported operating systems

The Wazuh indexer runs on 64-bit Linux, on x86_64 (AMD64) or aarch64 (ARM64) processors. See [Compatibility](../compatibility.md#supported-operating-systems) for the supported distributions and versions.

### Hardware recommendations

The Wazuh indexer can be installed as a single-node or as a multi-node cluster.

#### Hardware recommendations for each node

<table><thead>
  <tr>
    <th></th>
    <th colspan="2">Minimum</th>
    <th colspan="2">Recommended</th>
  </tr>
  <tr>
    <td>Component</td>
    <td>RAM (GB)</td>
    <td>CPU (cores)</td>
    <td>RAM (GB)</td>
    <td>CPU (cores)</td>
  </tr></thead>
  <tbody>
  <tr>
    <td>Wazuh indexer</td>
    <td>8</td>
    <td>4</td>
    <td>16</td>
    <td>8</td>
  </tr>
</tbody>
</table>

#### Disk space requirements

The amount of data depends on the generated events per second (EPS). This table details the estimated disk space needed per agent to store 90 days of events on a Wazuh indexer server, depending on the type of monitored endpoints.

| Monitored endpoints | EPS  | Storage in Wazuh indexer (GB/90 days) |
|---------------------|------|---------------------------------------|
| Servers             | 0.25 | 3.7                                   |
| Workstations        | 0.1  | 1.5                                   |
| Network devices     | 0.5  | 7.4                                   |

For example, for an environment with 80 workstations, 10 servers, and 10 network devices, the storage needed on the Wazuh indexer server for 90 days of events is 231 GB.

### Network ports

Allow the following inbound traffic on every Wazuh indexer node:

- **`9200/TCP`** — REST API, over HTTPS. Must be reachable from the Wazuh Manager and Wazuh Dashboard nodes, and from any client that uses the API.
- **`9300/TCP`** — transport, the communication between the nodes of a cluster, over TLS. Must be reachable from every other Wazuh indexer node. A single-node deployment does not need to expose it.

These are the default ports; `http.port` and `transport.port` in `/etc/wazuh-indexer/opensearch.yml` change them.

The Content Manager plugin also connects out to the Wazuh Cyber Threat Intelligence (CTI) API over HTTPS (`443/TCP`) to synchronize content, check for updates and send telemetry. An installation without internet access can disable those tasks instead; see [Offline configuration](../modules/content-manager/configuration.md#offline-configuration--disabling-automatic-updates).
