# How to Build from Sources

The Wazuh Indexer Plugins repository uses Gradle as its build system. The root project contains multiple subprojects, one per plugin.

## Building the Entire Project

To build all plugins (compile, test, and package):

```bash
./gradlew build
```

When completed, distribution artifacts for each plugin are located in their respective `build/distributions/` directories.

## Building a Specific Plugin

To build only the Content Manager plugin:

```bash
./gradlew :wazuh-indexer-content-manager:build
```

Other plugin targets follow the same pattern. To see all available projects:

```bash
./gradlew projects
```

## Compile Only (No Tests)

For a faster feedback loop during development, compile without running tests:

```bash
./gradlew :wazuh-indexer-content-manager:compileJava
```

This is useful for checking that your code changes compile correctly before running the full test suite.

## Output Locations

| Artifact | Location |
|---|---|
| Plugin ZIP distribution | `plugins/<plugin-name>/build/distributions/` |
| Compiled classes | `plugins/<plugin-name>/build/classes/` |
| Test reports | `plugins/<plugin-name>/build/reports/tests/` |
| Generated JARs | `plugins/<plugin-name>/build/libs/` |

## Common Build Issues

### JDK Version Mismatch

The project requires a specific JDK version (currently JDK 24, Eclipse Temurin). If you see compilation errors related to Java version, check:

```bash
java --version
```

Ensure `JAVA_HOME` points to the correct JDK. See [Setup](setup.md) for details.

### Dependency Resolution Failures

If Gradle cannot resolve dependencies:

1. Check your network connection (dependencies are downloaded from Maven Central and repositories).
2. Try clearing the Gradle cache: `rm -rf ~/.gradle/caches/`
3. Re-run with `--refresh-dependencies`: `./gradlew build --refresh-dependencies`

### Out of Memory

For large builds, increase Gradle's heap size in `gradle.properties`:

```properties
org.gradle.jvmargs=-Xmx4g
```

### Linting and Formatting Errors

The build includes code quality checks (Spotless, etc.). If formatting checks fail:

```bash
./gradlew spotlessApply
```

Then rebuild.

## Useful Gradle Flags

| Flag | Description |
|---|---|
| `--info` | Verbose output |
| `--debug` | Debug-level output |
| `--stacktrace` | Print stack traces on failure |
| `--parallel` | Run tasks in parallel (faster on multi-core) |
| `-x test` | Skip tests: `./gradlew build -x test` |
| `--continuous` | Watch mode — rebuilds on file changes |
