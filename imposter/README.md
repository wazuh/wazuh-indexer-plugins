## Imposter Introduction

Imposter is a mock server that we use to simulate responses from the Wazuh Manager API, allowing testing and development without a live backend.

### Prerequisites

To use Imposter, you will need a Java Virtual Machine (JVM) installed.

### Installation

To use Imposter for testing during development, you first need to install it by following the [Imposter installation guide](https://github.com/gatehill/imposter-cli/blob/main/docs/install.md).

### Configuration

The OpenAPI specification for our service is defined by the URL in the `specFile` attribute within `wazuh-server-config.yaml`. This setup ensures that the specification is automatically updated with new versions.

In `wazuh-server-config.yaml`, you can also find the configurations for specific endpoints used in our plugins. If you need to modify the default response for any endpoint, adjust the `statusCode` attribute accordingly. The possible values for `statusCode` are outlined in the OpenAPI `specFile`.

### Usage

After installing Imposter, set up a new Imposter instance using the following command:

```bash
IMPOSTER_OPENAPI_REMOTE_FILE_CACHE=true IMPOSTER_JS_PLUGIN=js-graal-compat imposter up -p 55000 -t jvm
```

- `IMPOSTER_OPENAPI_REMOTE_FILE_CACHE=true` enables caching the `specFile`.
- `IMPOSTER_JS_PLUGIN=js-graal-compat` allows compatibility with JavaScript libraries for dynamic loading.

Once Imposter is running, you can access the Swagger documentation at [http://localhost:55000/_spec/](http://localhost:55000/_spec/). Use this interface for browsing specifications or testing with tools like `curl`, or integrate it directly into your development tests.

### Useful Imposter Commands

- **Check Setup**: Run the following command to verify that everything is in place to start Imposter:

  ```bash
  imposter doctor
  ```

This command checks the configuration and dependencies to ensure Imposter can run correctly.
