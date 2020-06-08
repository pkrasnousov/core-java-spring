package eu.arrowhead.core.serviceregistry.protocols.mqtt;

import com.fasterxml.jackson.databind.ObjectMapper;

import eu.arrowhead.common.CommonConstants;
import eu.arrowhead.common.CoreDefaults;
import eu.arrowhead.common.CoreCommonConstants;
import eu.arrowhead.common.CoreUtilities;
import eu.arrowhead.common.Utilities;
import eu.arrowhead.common.core.CoreSystemService;
import eu.arrowhead.common.dto.internal.ServiceDefinitionRequestDTO;
import eu.arrowhead.common.dto.shared.ServiceQueryFormDTO;
import eu.arrowhead.common.dto.shared.ServiceRegistryRequestDTO;
import eu.arrowhead.common.dto.shared.ServiceSecurityType;
import eu.arrowhead.common.dto.shared.SystemRequestDTO;
import eu.arrowhead.core.serviceregistry.database.service.ServiceRegistryDBService;

import java.time.format.DateTimeParseException;
import java.util.Map;
import javax.annotation.PostConstruct;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Sort.Direction;
import org.springframework.stereotype.Component;

@Component
public class MqttServiceRegistry {

    //=================================================================================================
    // members    
    private final Logger logger = LogManager.getLogger(MqttServiceRegistry.class);

    @Value(CoreCommonConstants.$ORCHESTRATOR_IS_GATEKEEPER_PRESENT_WD)
    private boolean gatekeeperIsPresent;

    @Autowired
    private ServiceRegistryDBService serviceRegistryDBService;

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


    //=================================================================================================
    // methods
    //-------------------------------------------------------------------------------------------------
    @PostConstruct
    public void init() {
        logger.info("\n\nMQTT protocol\n\n");
        logger.info(serviceRegistryDBService);
        logger.info("working!\n\n");
        logger.info(mqttBrokerEnabled);
        logger.info(mqttBrokerAddress);
        logger.info(mqttBrokerPort);
        logger.info(serverSslEnabled);
        logger.info(keyStoreType);
        logger.info(keyStorePath);
        logger.info(keyStorePassword);
        logger.info(keyPassword);
        logger.info(trustStorePath);
        logger.info(trustStorePassword);
        // Start MQTT here
        logger.info("Starting MQTT");
    }

}
