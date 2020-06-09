package eu.arrowhead.core.orchestrator.protocols.mqtt;

import eu.arrowhead.core.orchestrator.protocols.coap.*;
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
import eu.arrowhead.core.orchestrator.service.OrchestratorService;

import org.springframework.beans.factory.annotation.Value;

import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttCallback;
import org.eclipse.paho.client.mqttv3.IMqttDeliveryToken;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttException;
import org.eclipse.paho.client.mqttv3.MqttMessage;
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence;

@Component
public class MqttOrchestrator implements MqttCallback, Runnable {

    //=================================================================================================
    // members    
    private final Logger logger = LogManager.getLogger(MqttOrchestrator.class);

    @Value(CoreCommonConstants.$ORCHESTRATOR_IS_GATEKEEPER_PRESENT_WD)
    private boolean gatekeeperIsPresent;

    @Autowired
    private OrchestratorService orchestratorService;

    @Value(CoreCommonConstants.$MQTT_BROKER_ENABLED)
    private boolean mqttBrokerEnabled;

    @Value(CoreCommonConstants.$MQTT_BROKER_ADDRESS)
    private String mqttBrokerAddress;

    @Value(CoreCommonConstants.$MQTT_BROKER_PORT)
    private int mqttBrokerPort;

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

    Thread t = null;

    //=================================================================================================
    // methods
    //-------------------------------------------------------------------------------------------------
    @PostConstruct
    public void init() {
        logger.info("MQTT protocol");
        if (mqttBrokerEnabled) {
            logger.info("Starting MQTT");

	    /* connect to MQTT Broker */

	    t = new Thread(this);
	    t.start();
        }
    }

    //=================================================================================================
    // assistant methods
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
    
    @Override
    public void run() {
      try {
	while(true) {
	  //logger.info("MQTT timeut thread");
          Thread.sleep(1000);
	}
      } catch(InterruptedException iex) {
        logger.info("Error starting MQTT timeout thread");
      }
    
    }

    @Override
    public void connectionLost(Throwable cause) {
    
    }
    
    @Override
    public void messageArrived(String topic, MqttMessage message) {
    
    }

    @Override
    public void deliveryComplete(IMqttDeliveryToken token) {
    
    }

    /* /echo - GET 
    exchange.respond(
                    CoAP.ResponseCode.CONTENT,
                    "Got it!",
                    MediaTypeRegistry.TEXT_PLAIN);
    */
    
    /* /orchestrator - POST 
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
    */
    
    /* /orchestrator - GET 
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
    */
    
}
