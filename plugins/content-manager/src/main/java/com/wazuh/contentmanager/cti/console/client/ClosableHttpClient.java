package com.wazuh.contentmanager.cti.console.client;

/**
 * Represents a closable HTTP client wrapper used within the CTI console context.
 */
public interface ClosableHttpClient {

    /**
     * Sets the underlying API client instance to be used by this implementation.
     *
     * @param c the {@link ApiClient} instance to assign to this closable client.
     */
    void setClient(ApiClient c);

    /**
     * Closes this client and releases any system resources associated with it.
     */
    void close();
}
