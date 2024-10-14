package com.wazuh.commandmanager.settings;

import org.junit.After;
import org.junit.Before;
import org.opensearch.common.settings.KeyStoreWrapper;
import org.opensearch.common.settings.SecureSettings;
import org.opensearch.core.common.settings.SecureString;
import org.opensearch.env.Environment;
import org.opensearch.test.OpenSearchIntegTestCase;

import java.nio.file.Path;

import static org.mockito.Mockito.*;

@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class PluginSettingsTest extends OpenSearchIntegTestCase {

    private PluginSettings pluginSettings;
    private Environment mockEnvironment;
    private final SecureString secureString = new SecureString("dummyPassword".toCharArray());

    @Before
    public void setUp() {
        // Create a mock Environment
        mockEnvironment = mock(Environment.class);
        // Instantiate PluginSettings
        pluginSettings = PluginSettings.getPluginSettingsInstance();
        pluginSettings.setEnv(mockEnvironment);
    }

    @After
    public void closeSecureString() {
        // Cleanup if necessary
        secureString.close();
    }

    public void testLoadSecureSettings_keystoreNotExist() throws Exception {
        // Setup the mock to return a specific path for the config file
        Path keyStorePath = Path.of("plugins/command-manager/src/test/resources/wazuh-indexer.keystoreUNEXISTENT.json");
        when(mockEnvironment.configFile()).thenReturn(keyStorePath);

        // Mocking the keyStoreWrapper to return null
        KeyStoreWrapper keyStoreWrapperMock = mock(KeyStoreWrapper.class);
        when(KeyStoreWrapper.load(any(), any())).thenReturn(null);

        // Check that the keystore is created
        SecureSettings result = pluginSettings.loadSecureSettings(secureString);

        assertNotNull(result);
        verify(keyStoreWrapperMock, times(1)).save(any(), any());
    }

    public void testLoadSecureSettings_keystoreExists() throws Exception {
        // Setup the mock to return a specific path for the config file
        Path keyStorePath = Path.of("plugins/command-manager/src/test/resources/");
        when(mockEnvironment.configFile()).thenReturn(keyStorePath);

        // Simulate an existing keystore
        KeyStoreWrapper keyStoreWrapperMock = KeyStoreWrapper.load(keyStorePath, "wazuh-indexer.keystore.json");
        when(KeyStoreWrapper.load(any(), any())).thenReturn(keyStoreWrapperMock);
        String text = "type";
        char[] passToTest = text.toCharArray();
        keyStoreWrapperMock.decrypt(passToTest);

        // Load secure settings
        SecureSettings result = pluginSettings.loadSecureSettings(secureString);

        assertNotNull(result);
        verify(keyStoreWrapperMock, times(1)).decrypt(secureString.getChars());
    }
}
