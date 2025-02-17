# Requirements

## Recommended operating systems

The Wazuh indexer requires a 64-bit Intel or AMD Linux processor (x86_64/AMD64 architecture) to run. Wazuh supports the following operating system versions:

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

## Hardware recommendations

The Wazuh indexer can be installed as a single-node or as a multi-node cluster.

- Hardware recommendations for each node

<table><thead>
  <tr>
    <th></th>
    <th colspan="2">Minimum</th>
    <th colspan="2">Recommended</th>
  </tr></thead>
<tbody>
  <tr>
    <td>Component</td>
    <td>RAM (GB)</td>
    <td>CPU (cores)</td>
    <td>RAM (GB)</td>
    <td>CPU (cores)</td>
  </tr>
  <tr>
    <td>Wazuh indexer</td>
    <td>4</td>
    <td>2</td>
    <td>16</td>
    <td>8</td>
  </tr>
</tbody>
</table>

- Disk space requirements

The amount of data depends on the generated alerts per second (APS). This table details the estimated disk space needed per agent to store 90 days of alerts on a Wazuh indexer server, depending on the type of monitored endpoints.


<table><thead>
  <tr>
    <th>Monitored endpoints</th>
    <th>APS</th>
    <th>Storage in Wazuh indexer <br> (GB/90 days)</th>
  </tr></thead>
<tbody>
  <tr>
    <td>Servers</td>
    <td>0.25</td>
    <td>3.7</td>
  </tr>
  <tr>
    <td>Workstations</td>
    <td>0.1</td>
    <td>1.5</td>
  </tr>
  <tr>
    <td>Network devices</td>
    <td>0.5</td>
    <td>7.4</td>
  </tr>
</tbody>
</table>

For example, for an environment with 80 workstations, 10 servers, and 10 network devices, the storage needed on the Wazuh indexer server for 90 days of alerts is 230 GB.