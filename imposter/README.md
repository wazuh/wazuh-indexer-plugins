## Imposter introduction

Imposter is a mock server that we are using it to generate a mock from the Wazuh Manager OpenAPI.

### Installation
For our use you will need to have a JVM installed.

To use it for testing during development, you first need to [install Imposter](https://github.com/gatehill/imposter-cli/blob/main/docs/install.md)

### Our configuration
The spec of our OpenApi service is the URL specified inside the specFile attribute in wazuh-manager-config.yaml. The purpose of this is to have it automatically updated with new versions.

Inside wazuh-manager-config.yaml we can also find the configuration of the specific endpoints that we will use in our plugins. In the case of wanting to modify the default response of these endpoints, the corresponding statusCode must be changed, understanding that the possible options are those found in the specFile.

### Use
Once Imposter is installed, we need to install a new Imposter instance:
`IMPOSTER_OPENAPI_REMOTE_FILE_CACHE=true IMPOSTER_JS_PLUGIN=js-graal-compat imposter up -p 55000 -t jvm`

IMPOSTER_OPENAPI_REMOTE_FILE_CACHE being the environment variable that allows us to use a specFile defined through a URL and IMPOSTER_JS_PLUGIN the one that allows us to use a JavaScript version compatible with the dynamic loading of libraries.

Once the Imposter is up you can access to a swagger with the specifications in http://localhost:55000/_spec/ and you can also test it with curl or point it in your development tests.

### Interesting Imposter commands
To verify if we have what we need to verify if we have what we need to raise Imposter:
`imposter doctor`