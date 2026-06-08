# Configuration

Wazuh Indexer shares the same configuration system as OpenSearch. Refer to the [OpenSearch documentation](https://docs.opensearch.org/3.6/install-and-configure/configuring-opensearch/index/) for general information about configuration files and settings.

## Configuration files

Wazuh Indexer bundles two main configuration files on each node:

- `/etc/wazuh-indexer/opensearch.yml` - main configuration file for Wazuh Indexer. This file contains the settings for the Wazuh Indexer cluster, such as cluster name, node name, network settings, and more.
- `/etc/wazuh-indexer/jvm.options` - configuration file for the Java Virtual Machine (JVM) that runs Wazuh Indexer. This file contains settings for the JVM, such as heap size, garbage collection, and more.

## System configuration

For production workloads, tune the following operating system and JVM settings on every Wazuh Indexer node before starting the service. The package installations create the `wazuh-indexer` service user; the settings below apply to that user and the host it runs on.

> **Note**: All the commands in this section require root privileges.

## JVM heap size

Wazuh Indexer runs on the Java Virtual Machine (JVM). The heap size determines how much memory the indexer can use for its internal data structures, caches, and request processing. Set it in the `/etc/wazuh-indexer/jvm.options` file.

Follow these recommendations when sizing the heap:

- Set the initial heap size (`-Xms`) and the maximum heap size (`-Xmx`) to the same value. This prevents performance degradation caused by the JVM resizing the heap at runtime.
- Set the heap to no more than 50% of the available system RAM. The other half is left for the operating system file system cache, which Wazuh Indexer relies on heavily.
- Do not set the heap above approximately 32 GB. Above this threshold the JVM can no longer use compressed ordinary object pointers, which wastes memory and reduces performance.

For example, on a node with 8 GB of RAM, set the heap to 4 GB:

```init
-Xms4g
-Xmx4g
```

Where:

- `-Xms4g` sets the initial heap size to 4 GB.
- `-Xmx4g` sets the maximum heap size to 4 GB.

Restart the service after changing the heap size:

```console
systemctl restart wazuh-indexer
```

## Disable swapping

When the operating system swaps Wazuh Indexer memory to disk, performance and node stability degrade severely, and the JVM can suffer long garbage collection pauses. Disable swapping on production nodes using one of the following approaches. Disabling all swap and enabling memory locking are the preferred options.

**Disable all swap files.** This is the most direct approach. To disable swap temporarily without restarting the service:

```console
swapoff -a
```

To make the change permanent, edit `/etc/fstab` and comment out any line that contains the word `swap`.

**Reduce swappiness.** If you cannot disable swap entirely, reduce the kernel's tendency to swap by setting `vm.swappiness` to `1`. Add the following line to `/etc/sysctl.conf`:

```
vm.swappiness=1
```

Apply the change with `sysctl -p`.

## Memory locking

As an alternative or complement to disabling swap, configure Wazuh Indexer to lock its process address space into RAM so that none of the JVM is ever swapped out.

1. Enable memory locking in the `/etc/wazuh-indexer/opensearch.yml` configuration file:

   ```yaml
   bootstrap.memory_lock: true
   ```

2. Grant the `wazuh-indexer` service user permission to lock unlimited memory. For systemd-based systems, create a service override:

   ```console
   mkdir -p /etc/systemd/system/wazuh-indexer.service.d/
   cat > /etc/systemd/system/wazuh-indexer.service.d/override.conf << EOF
   [Service]
   LimitMEMLOCK=infinity
   EOF
   ```

   For SysVinit-based systems, add the following lines to `/etc/security/limits.conf`:

   ```
   wazuh-indexer soft memlock unlimited
   wazuh-indexer hard memlock unlimited
   ```

3. Reload the service manager and restart Wazuh Indexer:

   ```console
   systemctl daemon-reload
   systemctl restart wazuh-indexer
   ```

4. Verify that memory locking is active by checking that the `mlockall` value is `true`:

   ```console
   curl -k -u <INDEXER_USERNAME>:<INDEXER_PASSWORD> "https://<INDEXER_IP_ADDRESS>:9200/_nodes?filter_path=**.mlockall&pretty"
   ```

   ```
   {
     "nodes" : {
       "sRuGbIQRRfC54wzwIHjJWQ" : {
         "process" : {
           "mlockall" : true
         }
       }
     }
   }
   ```

   If the output is `false`, memory locking failed and the following line appears in `/var/log/wazuh-indexer/wazuh-indexer.log`:

   ```
   memory locking requested for wazuh-indexer process but memory is not locked
   ```

   This usually means the `wazuh-indexer` user lacks the `memlock` permission. Confirm that step 2 was applied correctly, reload with `systemctl daemon-reload`, and restart the service.

> **Note**: Enabling `bootstrap.memory_lock` causes the JVM to reserve all the memory it needs at startup, including native memory beyond the configured heap. Make sure the node has enough physical RAM for the heap plus this overhead, otherwise the service may fail to start.

## Virtual memory

Wazuh Indexer uses memory-mapped files (`mmapfs`) to store its indices. The default operating system limit on memory map areas is too low for production use, which can cause the node to fail to start or run out of memory.

Set `vm.max_map_count` to at least `262144`. To check the current value:

```console
sysctl vm.max_map_count
```

To increase it permanently, add the following line to `/etc/sysctl.conf`:

```
vm.max_map_count=262144
```

Apply the change without rebooting:

```console
sysctl -p
```

> **Note**: When running Wazuh Indexer in a container, set `vm.max_map_count` on the host machine, not inside the container.

## File descriptors

Wazuh Indexer uses a large number of file descriptors. Running out of them can lead to data loss, so increase the limit for the `wazuh-indexer` user to `65535` or higher.

The RPM and Debian packages already set this limit to `65535` through the systemd service, so no additional configuration is required for package installations. To raise the limit manually, create or edit a systemd service override:

```console
mkdir -p /etc/systemd/system/wazuh-indexer.service.d/
cat > /etc/systemd/system/wazuh-indexer.service.d/override.conf << EOF
[Service]
LimitNOFILE=65535
EOF
```

Reload and restart the service:

```console
systemctl daemon-reload
systemctl restart wazuh-indexer
```

Verify the limit applied to the running node by checking `max_file_descriptors`:

```console
curl -k -u <INDEXER_USERNAME>:<INDEXER_PASSWORD> "https://<INDEXER_IP_ADDRESS>:9200/_nodes/stats/process?filter_path=**.max_file_descriptors&pretty"
```

## Related documentation

- [Security settings](../security)
- [Plugin settings](plugin-settings.md)
