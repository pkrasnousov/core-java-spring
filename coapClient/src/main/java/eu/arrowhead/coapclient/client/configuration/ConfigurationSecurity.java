package eu.arrowhead.coapclient.client.configuration;

public class ConfigurationSecurity {

    private final String clientAlias;
    private final String keyStoreFile;
    private final String keyStorePassword;
    private final String trustAlias;
    private final String trustStoreFile;
    private final String trustStorePassword;

    public ConfigurationSecurity(String clientAlias, String keyStoreFile, String keyStorePassword, String trustAlias, String trustStoreFile, String trustStorePassword) {
        this.clientAlias = clientAlias;
        this.keyStoreFile = keyStoreFile;
        this.keyStorePassword = keyStorePassword;
        this.trustAlias = trustAlias;
        this.trustStoreFile = trustStoreFile;
        this.trustStorePassword = trustStorePassword;
    }
    
    public String getClientAlias() {
        return clientAlias;
    }
    
    public String getKeyStoreFile() {
        return keyStoreFile;
    }
    
    public String getKeyStorePassword() {
        return keyStorePassword;
    }
    
    public char[] getKeyStorePasswordAsCharArray() {
        return keyStorePassword.toCharArray();
    }
    
    public String getTrustAlias() {
        return trustAlias;
    }
    
    public String getTrustStoreFile() {
        return trustStoreFile;
    }
    
    public String getTrustStorePassword() {
        return trustStorePassword;
    }
    
    public char[] getTrustStorePasswordAsCharArray() {
        return trustStorePassword.toCharArray();
    }

}
