/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.auth;

public interface HTTPAuthenticator {

    //    String getType();

    AuthCredentials getCredentials();

    void authenticate();

    //    Optional<SimpleResponse> reAuthenticate(AuthCredentials credentials);

}
