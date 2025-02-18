# Requirements

## Hardware recommendations

The Wazuh indexer can be installed as a single-node or as a multi-node cluster.

### Hardware recommendations for each node

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
    <td>4</td>
    <td>2</td>
    <td>16</td>
    <td>8</td>
  </tr>
</tbody>
</table>

### Disk space requirements

The amount of data depends on the generated alerts per second (APS). This table details the estimated disk space needed per agent to store 90 days of alerts on a Wazuh indexer server, depending on the type of monitored endpoints.

| Monitored endpoints | APS  | Storage in Wazuh indexer (GB/90 days) |
|---------------------|------|---------------------------------------|
| Servers             | 0.25 | 3.7                                   |
| Workstations        | 0.1  | 1.5                                   |
| Network devices     | 0.5  | 7.4                                   |


For example, for an environment with 80 workstations, 10 servers, and 10 network devices, the storage needed on the Wazuh indexer server for 90 days of alerts is 230 GB.