package com.wazuh.commandmanager.settings;

import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;


public class PluginSettings {
    public static final String BASE_PLUGINS_URI = "/_plugins";
    // Command Manager settings
    public static final Setting<Integer> TIMEOUT = Setting.intSetting("command_manager.timeout", Integer.MIN_VALUE, Setting.Property.NodeScope, Setting.Property.Filtered);
    // Command Manager Job settings
    public static final Setting<String> JOB_SCHEDULE = Setting.simpleString("command_manager.job.schedule", Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Integer> JOB_PAGE_SIZE = Setting.intSetting("command_manager.job.page_size", Integer.MIN_VALUE, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Integer> JOB_KEEP_ALIVE = Setting.intSetting("command_manager.job.pit_keep_alive", Integer.MIN_VALUE, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> JOB_INDEX_NAME = Setting.simpleString("command_manager.job.index.name", Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> JOB_INDEX_TEMPLATE = Setting.simpleString("command_manager.job.index.template", Setting.Property.NodeScope, Setting.Property.Filtered);
    // Command Manager API settings
    public static final Setting<String> API_PREFIX = Setting.simpleString("command_manager.api.prefix", Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> API_ENDPOINT = Setting.simpleString("command_manager.api.endpoint", Setting.Property.NodeScope, Setting.Property.Filtered);
    // Command Manager Index settings
    public static final Setting<String> INDEX_NAME = Setting.simpleString("command_manager.index.name", Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> INDEX_TEMPLATE = Setting.simpleString("command_manager.index.template", Setting.Property.NodeScope, Setting.Property.Filtered);

    private final Integer timeout;
    private final String jobSchedule;
    private final Integer jobPageSize;
    private final Integer jobKeepAlive;
    private final String jobIndexName;
    private final String jobIndexTemplate;
    private final String apiPrefix;
    private final String apiEndpoint;
    private final String indexName;
    private final String indexTemplate;

    /** Private default constructor */
    private PluginSettings(@NonNull final Settings settings) {
        this.timeout = TIMEOUT.get(settings);
        this.jobSchedule = JOB_SCHEDULE.get(settings);
        this.jobPageSize = JOB_PAGE_SIZE.get(settings);
        this.jobKeepAlive = JOB_KEEP_ALIVE.get(settings);
        this.jobIndexName = JOB_INDEX_NAME.get(settings);
        this.jobIndexTemplate = JOB_INDEX_TEMPLATE.get(settings);
        this.apiPrefix = API_PREFIX.get(settings);
        this.apiEndpoint = API_ENDPOINT.get(settings);
        this.indexName = INDEX_NAME.get(settings);
        this.indexTemplate = INDEX_TEMPLATE.get(settings);

        this.apiBaseUri = BASE_PLUGINS_URI + apiPrefix;
        this.apiCommandsUri = apiBaseUri + apiEndpoint;
    }

    /**
     * Singleton instance accessor. Initializes the settings
     *
     * @return {@link PluginSettings#instance}
     */
    public static PluginSettings getInstance(@NonNull final Settings settings) {
        if (PluginSettings.instance == null) {
            instance = new PluginSettings(settings);
        }
        return instance;
    }

    /**
     * Singleton instance accessor
     *
     * @return {@link PluginSettings#instance}
     */
    public static PluginSettings getInstance() {
        if (PluginSettings.instance == null) {
            throw new IllegalStateException("Plugin settings have not been initialized.");
        }
        return instance;
    }

    public Integer getTimeout() {
        return timeout;
    }

    public String getJobSchedule() {
        return jobSchedule;
    }

    public Integer getJobPageSize() {
        return jobPageSize;
    }

    public Integer getJobKeepAlive() {
        return jobKeepAlive;
    }

    public String getJobIndexName() {
        return jobIndexName;
    }

    public String getJobIndexTemplate() {
        return jobIndexTemplate;
    }

    public String getApiBaseUri() {
        return apiBaseUri;
    }

    public String getApiCommandsUri() {
        return apiCommandsUri;
    }

    public String getIndexName() {
        return indexName;
    }

    public String getIndexTemplate() {
        return indexTemplate;
    }

    @Override
    public String toString() {
        return "PluginSettings{" +
                "timeout=" + timeout +
                ", jobSchedule='" + jobSchedule + '\'' +
                ", jobPageSize=" + jobPageSize +
                ", jobKeepAlive=" + jobKeepAlive +
                ", jobIndexName='" + jobIndexName + '\'' +
                ", jobIndexTemplate='" + jobIndexTemplate + '\'' +
                ", apiBaseUri='" + apiBaseUri + '\'' +
                ", apiCommandsUri='" + apiCommandsUri + '\'' +
                ", indexName='" + indexName + '\'' +
                ", indexTemplate='" + indexTemplate + '\'' +
                '}';
    }

    private static PluginSettings instance;
}
