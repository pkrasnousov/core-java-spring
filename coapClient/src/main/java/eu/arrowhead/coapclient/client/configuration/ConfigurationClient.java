package eu.arrowhead.coapclient.client.configuration;

public class ConfigurationClient {

    private final static int DEFAULT_PORT = 5684;
    private final static int DEFAULT_SECURED_PORT = 5683;
    private final static String DEFAULT_SCHEME = "coap";
    private final static String DEFAULT_SECURED_SCHEME = "coaps";
    private final boolean secured;
    private final String host;
    private final int port;
    private final String path;
    private final ConfigurationSecurity security;

    public ConfigurationClient(boolean secured, String serverHost, int serverPort, String serverPath, ConfigurationSecurity security) {
        this.secured = secured;
        host = serverHost;
        port = serverPort;
        path = serverPath;
        this.security = security;
    }

    public boolean isSecured() {
        return secured;
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return (port <= 0) ? secured ? DEFAULT_SECURED_PORT : DEFAULT_PORT : port;
    }

    public String getPath() {
        return path;
    }

    public String getScheme() {
        return secured ? DEFAULT_SECURED_SCHEME : DEFAULT_SCHEME;
    }
    
    public String getUriString() {
        return String.format("%s://%s:%d/%s",
                getScheme(),
                getHost(),
                getPort(),
                getPath().isEmpty()?"":getPath().endsWith("/")?getPath():getPath()+"/");
    }
    
    public ConfigurationSecurity getSecurityConfiguration() {
        return security;
    }

}
