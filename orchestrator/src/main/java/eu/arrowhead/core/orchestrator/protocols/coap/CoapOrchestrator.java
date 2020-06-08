package eu.arrowhead.core.orchestrator.protocols.coap;

import com.fasterxml.jackson.databind.ObjectMapper;
import javax.annotation.PostConstruct;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import eu.arrowhead.common.CommonConstants;
import eu.arrowhead.common.CoreCommonConstants;
import eu.arrowhead.common.Utilities;
import eu.arrowhead.common.dto.shared.CloudRequestDTO;
import eu.arrowhead.common.dto.shared.OrchestrationFlags.Flag;
import eu.arrowhead.common.dto.shared.OrchestrationFormRequestDTO;
import eu.arrowhead.common.dto.shared.PreferredProviderDataDTO;
import eu.arrowhead.common.dto.shared.SystemRequestDTO;
import eu.arrowhead.common.coap.AhCoapServer;
import eu.arrowhead.common.coap.configuration.CoapCertificates;
import eu.arrowhead.common.coap.configuration.CoapCredentials;
import eu.arrowhead.common.coap.configuration.CoapServerConfiguration;
import eu.arrowhead.common.coap.tools.CoapTools;
import eu.arrowhead.core.orchestrator.service.OrchestratorService;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;

import org.springframework.beans.factory.annotation.Value;

@Component
public class CoapOrchestrator {

    //=================================================================================================
    // members    
    private final Logger logger = LogManager.getLogger(CoapOrchestrator.class);
    private AhCoapServer coapServer;

    @Value(CoreCommonConstants.$ORCHESTRATOR_IS_GATEKEEPER_PRESENT_WD)
    private boolean gatekeeperIsPresent;

    @Autowired
    private OrchestratorService orchestratorService;

    @Value(CoreCommonConstants.$COAP_SERVER_ENABLED)
    private boolean coapServerEnabled;

    @Value(CoreCommonConstants.$COAP_SERVER_ADDRESS)
    private String coapServerAddress;

    @Value(CoreCommonConstants.$COAP_SERVER_PORT)
    private int coapServerPort;

    @Value(CommonConstants.$SERVER_SSL_ENABLED_WD)
    private boolean serverSslEnabled;

    @Value(CommonConstants.$KEYSTORE_TYPE)
    private String keyStoreType;

    @Value(CommonConstants.$KEYSTORE_PATH)
    private String keyStorePath;

    @Value(CommonConstants.$KEYSTORE_PASSWORD)
    private String keyStorePassword;

    @Value(CommonConstants.$KEY_PASSWORD)
    private String keyPassword;

    @Value(CommonConstants.$TRUSTSTORE_PATH)
    private String trustStorePath;

    @Value(CommonConstants.$TRUSTSTORE_PASSWORD)
    private String trustStorePassword;

    private final String URL_PATH_ORCHESTRATOR = "orchestrator";
    private final String URL_PATH_ID = "id";

    //=================================================================================================
    // methods
    //-------------------------------------------------------------------------------------------------
    @PostConstruct
    public void init() {
        logger.info("\n\nCOAP SERVER\n\n");
        logger.info(orchestratorService);
        logger.info("working!\n\n");
        logger.info(coapServerEnabled);
        logger.info(coapServerAddress);
        logger.info(coapServerPort);
        logger.info(serverSslEnabled);
        logger.info(keyStoreType);
        logger.info(keyStorePath);
        logger.info(keyStorePassword);
        logger.info(keyPassword);
        logger.info(trustStorePath);
        logger.info(trustStorePassword);
        if (coapServerEnabled) {
            coapServer = new AhCoapServer(new CoapServerConfiguration(
                    coapServerAddress,
                    coapServerPort,
                    serverSslEnabled,
                    new CoapCredentials(
                            keyStorePath,
                            keyStorePassword,
                            keyPassword,
                            "orchestrator-coap"
                    ),
                    new CoapCertificates(
                            "coap-root",
                            trustStorePassword,
                            trustStorePath
                    )
            ));

            initializateResources();
            coapServer.start();
        }

    }

    //=================================================================================================
    // assistant methods
    //-------------------------------------------------------------------------------------------------
    private void initializateResources() {
        coapServer.add(new EchoResource());
        coapServer.add(new OrchestratorResource());
    }

    //-------------------------------------------------------------------------------------------------	
    private void checkOrchestratorFormRequestDTO(final OrchestrationFormRequestDTO request, final String origin) throws Exception {
        if (request == null) {
            throw new Exception("Request null");
        }

        request.validateCrossParameterConstraints();

        // Requester system
        checkSystemRequestDTO(request.getRequesterSystem(), origin);

        // Requester cloud
        if (request.getRequesterCloud() != null) {
            checkCloudRequestDTO(request.getRequesterCloud(), origin);
        }

        // Requested service
        if (request.getRequestedService() != null && Utilities.isEmpty(request.getRequestedService().getServiceDefinitionRequirement())) {
            throw new Exception("Requested service definition requirement");
        }

        // Preferred Providers
        if (request.getPreferredProviders() != null) {
            for (final PreferredProviderDataDTO provider : request.getPreferredProviders()) {
                checkSystemRequestDTO(provider.getProviderSystem(), origin);
                if (provider.getProviderCloud() != null) {
                    checkCloudRequestDTO(provider.getProviderCloud(), origin);
                }
            }
        }
    }

    //-------------------------------------------------------------------------------------------------
    private void checkSystemRequestDTO(final SystemRequestDTO system, final String origin) throws Exception {
        logger.debug("checkSystemRequestDTO started...");

        if (system == null) {
            throw new Exception("System null");
        }

        if (Utilities.isEmpty(system.getSystemName())) {
            throw new Exception("System name null");
        }

        if (Utilities.isEmpty(system.getAddress())) {
            throw new Exception("System address null");
        }

        if (system.getPort() == null) {
            throw new Exception("System port null");
        }

        final int validatedPort = system.getPort().intValue();
        if (validatedPort < CommonConstants.SYSTEM_PORT_RANGE_MIN || validatedPort > CommonConstants.SYSTEM_PORT_RANGE_MAX) {
            throw new Exception("System port must be between " + CommonConstants.SYSTEM_PORT_RANGE_MIN + " and " + CommonConstants.SYSTEM_PORT_RANGE_MAX + ".");
        }
    }

    //-------------------------------------------------------------------------------------------------
    private void checkCloudRequestDTO(final CloudRequestDTO cloud, final String origin) throws Exception {
        logger.debug("checkCloudRequestDTO started...");

        if (cloud == null) {
            throw new Exception("Cloud null");
        }

        if (Utilities.isEmpty(cloud.getOperator())) {
            throw new Exception("Cloud operator null");
        }

        if (Utilities.isEmpty(cloud.getName())) {
            throw new Exception("Cloud name null");
        }
    }

    //=================================================================================================
    // CoAP resources
    //-------------------------------------------------------------------------------------------------
    class EchoResource extends CoapResource {

        public EchoResource() {
            super("echo");
            getAttributes().setTitle("Echo Resource");
        }

        @Override
        public void handleGET(CoapExchange exchange) {
            exchange.respond(
                    CoAP.ResponseCode.CONTENT,
                    "Got it!",
                    MediaTypeRegistry.TEXT_PLAIN);
        }

    }

    //-------------------------------------------------------------------------------------------------
    class OrchestratorResource extends CoapResource {

        private final ObjectMapper mapper = new ObjectMapper();

        public OrchestratorResource() {
            super(URL_PATH_ORCHESTRATOR);
            getAttributes().setTitle("Orchestrator Resource");
            add(new OrchestratorIdResource());
        }

        @Override
        public void handlePOST(CoapExchange exchange) {
            try {
                OrchestrationFormRequestDTO request = mapper.readValue(exchange.getRequestText(), OrchestrationFormRequestDTO.class);

                final String origin = CommonConstants.ORCHESTRATOR_URI + CommonConstants.OP_ORCH_PROCESS;
                checkOrchestratorFormRequestDTO(request, origin);

                if (request.getOrchestrationFlags().getOrDefault(Flag.EXTERNAL_SERVICE_REQUEST, false)) {
                    if (!gatekeeperIsPresent) {
                        throw new Exception("External service request, Gatekeeper is not present.");
                    }
                    exchange.respond(
                            ResponseCode.CONTENT,
                            mapper.writeValueAsString(orchestratorService.externalServiceRequest(request)),
                            MediaTypeRegistry.APPLICATION_JSON);
                } else if (request.getOrchestrationFlags().getOrDefault(Flag.TRIGGER_INTER_CLOUD, false)) {
                    if (!gatekeeperIsPresent) {
                        throw new Exception("External service request, Gatekeeper is not present.");
                    }
                    exchange.respond(
                            ResponseCode.CONTENT,
                            mapper.writeValueAsString(orchestratorService.triggerInterCloud(request)),
                            MediaTypeRegistry.APPLICATION_JSON);
                } else if (!request.getOrchestrationFlags().getOrDefault(Flag.OVERRIDE_STORE, false)) {
                    exchange.respond(
                            ResponseCode.CONTENT,
                            mapper.writeValueAsString(orchestratorService.orchestrationFromStore(request)),
                            MediaTypeRegistry.APPLICATION_JSON);
                } else {
                    exchange.respond(
                            ResponseCode.CONTENT,
                            mapper.writeValueAsString(orchestratorService.dynamicOrchestration(request)),
                            MediaTypeRegistry.APPLICATION_JSON);
                }

            } catch (Exception ex) {
                exchange.respond(
                        ResponseCode.INTERNAL_SERVER_ERROR,
                        ex.getMessage(),
                        MediaTypeRegistry.TEXT_PLAIN);
            }
        }

    }

    //-------------------------------------------------------------------------------------------------
    class OrchestratorIdResource extends CoapResource {

        private final ObjectMapper mapper = new ObjectMapper();

        public OrchestratorIdResource() {
            super(URL_PATH_ID);
            getAttributes().setTitle("Orchestrator Id Resource");
        }

        @Override
        public Resource getChild(String name) {
            return this;
        }

        @Override
        public void handleGET(CoapExchange exchange) {
            try {
                long systemId = Long.parseLong(CoapTools.getUrlPathValue(exchange, URL_PATH_ID));

                if (systemId < 1) {
                    throw new Exception("Id not valid");
                }

                exchange.respond(
                        ResponseCode.CONTENT,
                        mapper.writeValueAsString(orchestratorService.storeOchestrationProcessResponse(systemId)),
                        MediaTypeRegistry.APPLICATION_JSON);
            } catch (Exception ex) {
                exchange.respond(
                        ResponseCode.INTERNAL_SERVER_ERROR,
                        ex.getMessage(),
                        MediaTypeRegistry.TEXT_PLAIN);
            }
        }
    }
}
