package com.wazuh.commandmanager.scheduler;

import com.wazuh.commandmanager.config.reader.ConfigReader;

import java.util.function.Consumer;

public class JobSchedulerConsumer implements Consumer<ConfigReader> {
    @Override
    public void accept(ConfigReader configReader) {
    }

    @Override
    public Consumer<ConfigReader> andThen(Consumer<? super ConfigReader> after) {
        return Consumer.super.andThen(after);
    }
}
