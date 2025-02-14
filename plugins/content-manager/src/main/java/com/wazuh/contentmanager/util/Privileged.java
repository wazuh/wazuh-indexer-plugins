package com.wazuh.contentmanager.util;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;

import java.security.AccessController;

public class Privileged {

    public static SimpleHttpResponse doPrivilegedRequest(java.security.PrivilegedAction<SimpleHttpResponse> request) {
        return AccessController.doPrivileged(request);
    }
}
