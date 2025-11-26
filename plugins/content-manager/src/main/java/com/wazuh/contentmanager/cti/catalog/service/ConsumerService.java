package com.wazuh.contentmanager.cti.catalog.service;

import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.cti.catalog.model.RemoteConsumer;

public interface ConsumerService {

    LocalConsumer getLocalConsumer();
    RemoteConsumer getRemoteConsumer();
}
