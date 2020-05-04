package eu.arrowhead.coapclient;

import eu.arrowhead.coapclient.client.ServiceRegistryClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ArrowheadCoapClient {
    private static final Logger LOG = LoggerFactory.getLogger(ArrowheadCoapClient.class.getName());
    private final ServiceRegistryClient serviceRegistry;
    
    public ArrowheadCoapClient() {
        this.serviceRegistry = new ServiceRegistryClient();
    }
    
    public ServiceRegistryClient getServiceRegistry() {
        return serviceRegistry;
    }
}
