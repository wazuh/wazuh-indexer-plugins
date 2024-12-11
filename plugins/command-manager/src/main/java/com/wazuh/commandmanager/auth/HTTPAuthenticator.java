/*
 * Copyright (C) 2024 Wazuh
 * This file is part of Wazuh Indexer Plugins, which are licensed under the AGPLv3.
 *  See <https://www.gnu.org/licenses/agpl-3.0.txt> for the full text of the license.
 */
package com.wazuh.commandmanager.auth;

public interface HTTPAuthenticator {

    //    String getType();

    AuthCredentials getCredentials();

    void authenticate();

    //    Optional<SimpleResponse> reAuthenticate(AuthCredentials credentials);

}
