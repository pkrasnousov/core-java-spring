/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package eu.arrowhead.coapclient.client;

import eu.arrowhead.coapclient.client.configuration.ConfigurationClient;
import eu.arrowhead.coapclient.client.configuration.ConfigurationSecurity;
import java.io.FileNotFoundException;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.util.Properties;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.elements.exception.ConnectorException;

/**
 *
 * @author Pablo Puñal Pereira <pablo.punal@thingwave.eu>
 */
public class AuthorizationClient {

    private static final Logger LOG = LoggerFactory.getLogger(AuthorizationClient.class.getName());
    private static final String CONFIG_FILE = "client.properties";
    private static final String SERVICE_NAME = "authorization";
    private final ClientCoap clientCoap;

    public AuthorizationClient() {
        LOG.info("Create new OrchestratorClient");

        // Reading configuration!
        InputStream inputStream = getClass().getClassLoader().getResourceAsStream(CONFIG_FILE);
        Properties prop = new Properties();

        try {
            if (inputStream != null) {
                prop.load(inputStream);
            } else {
                throw new FileNotFoundException("property file '" + CONFIG_FILE + "' not found in the classpath");
            }
        } catch (Exception ex) {
            LOG.error("Exception: " + ex.getLocalizedMessage());
            System.exit(1);
        }

        clientCoap = new ClientCoap(new ConfigurationClient(
                Boolean.parseBoolean(prop.getProperty(SERVICE_NAME+".security.tls")),
                prop.getProperty(SERVICE_NAME+".host"),
                Integer.parseInt(prop.getProperty(SERVICE_NAME+".port")),
                prop.getProperty(SERVICE_NAME+".path"),
                new ConfigurationSecurity(
                        prop.getProperty(SERVICE_NAME+".security.client_alias"),
                        prop.getProperty(SERVICE_NAME+".security.keystore_file"),
                        prop.getProperty(SERVICE_NAME+".security.keystore_password"),
                        prop.getProperty(SERVICE_NAME+".security.trust_alias"),
                        prop.getProperty(SERVICE_NAME+".security.truststore_file"),
                        prop.getProperty(SERVICE_NAME+".security.truststore_password"))));
    }
    
    public CoapResponse getEcho() throws ConnectorException, IOException {
        CoapResponse response = clientCoap.GET("echo");
        return response;
    }
    
    public String getResources() throws ConnectorException, IOException {
        CoapResponse response = clientCoap.GET(".well-known/core");
        return formatResources(response);
    }
    
    public CoapResponse coapGET(String path) throws ConnectorException, IOException {
        CoapResponse response = clientCoap.GET(path);
        return response;
    }
    
    public CoapResponse coapPUT(String path)  throws ConnectorException, IOException {
        CoapResponse response = clientCoap.PUT(path,"",0);
        return response;
    }
    
    public CoapResponse coapPATCH(String path)  throws ConnectorException, IOException {
        CoapResponse response = clientCoap.PATCH(path,"",0);
        return response;
    }
    
    public CoapResponse coapPOST(String path)  throws ConnectorException, IOException {
        CoapResponse response = clientCoap.POST(path,"",0);
        return response;
    }
    
    public CoapResponse coapDELETE(String path) throws ConnectorException, IOException {
        CoapResponse response = clientCoap.DELETE(path);
        return response;
    }
        
    //--------------------------------------------------------------------------
    private String formatResources(CoapResponse response) {
        StringBuilder sb = new StringBuilder();
        String[] resources = response.getResponseText().split(",");
        sb.append("\nList of Resources:\n");
        for (String res: resources) {
            sb.append(res).append("\n");
        }
        return sb.toString();
    }

}
