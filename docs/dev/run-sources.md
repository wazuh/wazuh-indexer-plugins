# How to run from sources

Every Wazuh Indexer repository includes one or more Gradle projects with predefined tasks to run and build the source code.

In this case, to run a Gradle project from source code, run the `./gradlew run` command.

For Wazuh Indexer, additonal plugins may be installed by passing the `-PinstalledPlugins` flag:

```bash
./gradlew run -PinstalledPlugins="['plugin1', 'plugin2']"
```

The `./gradlew run` command will build and start the project, writing its log above Gradle's status message. A lot of stuff is logged on startup, specifically these lines tell you that OpenSearch is ready.

```
[2020-05-29T14:50:35,167][INFO ][o.e.h.AbstractHttpServerTransport] [runTask-0] publish_address {127.0.0.1:9200}, bound_addresses {[::1]:9200}, {127.0.0.1:9200}
[2020-05-29T14:50:35,169][INFO ][o.e.n.Node               ] [runTask-0] started
```

It's typically easier to wait until the console stops scrolling, and then run `curl` in another window to check if OpenSearch instance is running.

```bash
curl localhost:9200

{
  "name" : "runTask-0",
  "cluster_name" : "runTask",
  "cluster_uuid" : "oX_S6cxGSgOr_mNnUxO6yQ",
  "version" : {
    "number" : "1.0.0-SNAPSHOT",
    "build_type" : "tar",
    "build_hash" : "0ba0e7cc26060f964fcbf6ee45bae53b3a9941d0",
    "build_date" : "2021-04-16T19:45:44.248303Z",
    "build_snapshot" : true,
    "lucene_version" : "8.7.0",
    "minimum_wire_compatibility_version" : "6.8.0",
    "minimum_index_compatibility_version" : "6.0.0-beta1"
  }
}
```

Use `-Dtests.opensearch.` to pass additional settings to the running instance. For example, to enable OpenSearch to listen on an external IP address pass `-Dtests.opensearch.http.host`. Make sure your firewall or security policy allows external connections for this to work.

```bash
./gradlew run -Dtests.opensearch.http.host=0.0.0.0
```
