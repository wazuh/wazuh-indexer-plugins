package com.wazuh.commandmanager.spi;

public interface CommandManagerExtension {
    /**
     * @return command type string.
     */
    String getName();
}
