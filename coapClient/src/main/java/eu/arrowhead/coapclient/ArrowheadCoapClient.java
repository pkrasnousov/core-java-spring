package eu.arrowhead.coapclient;

import eu.arrowhead.coapclient.client.AuthorizationClient;
import eu.arrowhead.coapclient.client.OrchestratorClient;
import eu.arrowhead.coapclient.client.ServiceRegistryClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ArrowheadCoapClient {
    private static final Logger LOG = LoggerFactory.getLogger(ArrowheadCoapClient.class.getName());
    private final AuthorizationClient authorization;
    private final OrchestratorClient orchestrator;
    private final ServiceRegistryClient serviceRegistry;
    
    public ArrowheadCoapClient() {
        authorization = new AuthorizationClient();
        orchestrator = new OrchestratorClient();
        serviceRegistry = new ServiceRegistryClient();
    }
    
    public AuthorizationClient getAuthorization() {
        return authorization;
    }
    
    public OrchestratorClient getOrchestrator() {
        return orchestrator;
    }
    
    public ServiceRegistryClient getServiceRegistry() {
        return serviceRegistry;
    }
}
