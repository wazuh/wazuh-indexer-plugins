# How to build from sources

To build all distributions of OpenSearch, run:

```
./gradlew assemble
```

To build a distribution to run on your local platform, run:

```
./gradlew localDistro
```

All distributions built will be under `distributions/archives`.