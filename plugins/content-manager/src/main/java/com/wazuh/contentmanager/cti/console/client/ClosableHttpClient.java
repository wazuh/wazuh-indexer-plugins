package com.wazuh.contentmanager.cti.console.client;

public interface ClosableHttpClient {

    void setClient(ApiClient c);
    void close();
}
