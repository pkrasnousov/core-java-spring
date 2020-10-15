package eu.arrowhead.core.authorization.protocols.mqtt;

import eu.arrowhead.core.authorization.protocols.coap.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import javax.annotation.PostConstruct;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import eu.arrowhead.common.CommonConstants;
import eu.arrowhead.common.CoreCommonConstants;
import eu.arrowhead.common.Utilities;

import eu.arrowhead.common.dto.internal.AuthorizationInterCloudCheckRequestDTO;
import eu.arrowhead.common.dto.internal.AuthorizationInterCloudCheckResponseDTO;
import eu.arrowhead.common.dto.internal.AuthorizationInterCloudListResponseDTO;
import eu.arrowhead.common.dto.internal.AuthorizationInterCloudRequestDTO;
import eu.arrowhead.common.dto.internal.AuthorizationInterCloudResponseDTO;
import eu.arrowhead.common.dto.internal.AuthorizationIntraCloudCheckRequestDTO;
import eu.arrowhead.common.dto.internal.AuthorizationIntraCloudCheckResponseDTO;
import eu.arrowhead.common.dto.internal.AuthorizationIntraCloudListResponseDTO;
import eu.arrowhead.common.dto.internal.AuthorizationIntraCloudRequestDTO;
import eu.arrowhead.common.dto.internal.AuthorizationIntraCloudResponseDTO;
import eu.arrowhead.common.dto.internal.AuthorizationSubscriptionCheckRequestDTO;
import eu.arrowhead.common.dto.internal.AuthorizationSubscriptionCheckResponseDTO;
import eu.arrowhead.common.dto.internal.IdIdListDTO;
import eu.arrowhead.common.dto.internal.TokenDataDTO;
import eu.arrowhead.common.dto.internal.TokenGenerationProviderDTO;
import eu.arrowhead.common.dto.internal.TokenGenerationRequestDTO;
import eu.arrowhead.common.dto.internal.TokenGenerationResponseDTO;
import eu.arrowhead.common.dto.shared.SystemRequestDTO;

import eu.arrowhead.common.intf.ServiceInterfaceNameVerifier;
import eu.arrowhead.core.authorization.database.service.AuthorizationDBService;
import eu.arrowhead.core.authorization.token.TokenGenerationService;

import java.security.PublicKey;
import java.util.Base64;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import javax.annotation.Resource;

import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttCallback;
import org.eclipse.paho.client.mqttv3.IMqttDeliveryToken;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttException;
import org.eclipse.paho.client.mqttv3.MqttMessage;
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence;

@Component
public class MqttAuthorization {

    //=================================================================================================
    // members    
    private final Logger logger = LogManager.getLogger(MqttAuthorization.class);

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

    @Autowired
    private AuthorizationDBService authorizationDBService;

    @Autowired
    private TokenGenerationService tokenGenerationService;

    @Autowired
    private ServiceInterfaceNameVerifier interfaceNameVerifier;

    @Value(CommonConstants.$SERVER_SSL_ENABLED_WD)
    private boolean secure;

    @Resource(name = CommonConstants.ARROWHEAD_CONTEXT)
    private Map<String, Object> arrowheadContext;


    //=================================================================================================
    // methods
    //-------------------------------------------------------------------------------------------------
    @PostConstruct
    public void init() {
        logger.info("MQTT protocol");
        if (mqttBrokerEnabled) {
            logger.info("Starting MQTT");
        }
    }

    //=================================================================================================
    // assistant methods
    //-------------------------------------------------------------------------------------------------
    private String acquireAndConvertPublicKey() throws Exception {
        final String origin = CommonConstants.AUTHORIZATION_URI + CommonConstants.OP_AUTH_KEY_URI;

        if (!secure) {
            throw new Exception("Authorization core service runs in insecure mode.");
        }

        if (!arrowheadContext.containsKey(CommonConstants.SERVER_PUBLIC_KEY)) {
            throw new Exception("Public key is not available.");
        }

        final PublicKey publicKey = (PublicKey) arrowheadContext.get(CommonConstants.SERVER_PUBLIC_KEY);

        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    //-------------------------------------------------------------------------------------------------
    private void checkSystemRequest(final SystemRequestDTO system, final String origin, final boolean mandatoryAuthInfo) throws Exception {
        logger.debug("checkSystemRequest started...");

        if (Utilities.isEmpty(system.getSystemName())) {
            throw new Exception("System name is null or blank");
        }

        if (Utilities.isEmpty(system.getAddress())) {
            throw new Exception("System address is null or blank");
        }

        if (system.getPort() == null) {
            throw new Exception("System port is null");
        }

        final int validatedPort = system.getPort().intValue();
        if (validatedPort < CommonConstants.SYSTEM_PORT_RANGE_MIN || validatedPort > CommonConstants.SYSTEM_PORT_RANGE_MAX) {
            throw new Exception("System port must be between " + CommonConstants.SYSTEM_PORT_RANGE_MIN + " and " + CommonConstants.SYSTEM_PORT_RANGE_MAX + ".");
        }

        if (mandatoryAuthInfo && Utilities.isEmpty(system.getAuthenticationInfo())) {
            throw new Exception("System authentication info is null or blank");
        }
    }

    //-------------------------------------------------------------------------------------------------
    private void checkTokenGenerationRequest(final TokenGenerationRequestDTO request) throws Exception {
        logger.debug("checkTokenGenerationRequest started...");

        final String origin = CommonConstants.AUTHORIZATION_URI + CommonConstants.OP_AUTH_TOKEN_URI;
        if (request.getConsumer() == null) {
            throw new Exception("Consumer system is null");
        }

        checkSystemRequest(request.getConsumer(), origin, false);

        if (request.getConsumerCloud() != null && Utilities.isEmpty(request.getConsumerCloud().getOperator())) {
            throw new Exception("Consumer cloud's operator is null or blank");
        }

        if (request.getConsumerCloud() != null && Utilities.isEmpty(request.getConsumerCloud().getName())) {
            throw new Exception("Consumer cloud's name is null or blank");
        }

        if (request.getProviders() == null || request.getProviders().isEmpty()) {
            throw new Exception("Provider list is null or empty");
        }

        for (final TokenGenerationProviderDTO provider : request.getProviders()) {
            checkTokenGenerationProviderDTO(provider, origin);
        }

        if (Utilities.isEmpty(request.getService())) {
            throw new Exception("Service is null or blank");
        }
    }

    //-------------------------------------------------------------------------------------------------
    private void checkTokenGenerationProviderDTO(final TokenGenerationProviderDTO provider, final String origin) throws Exception {
        logger.debug("checkTokenGenerationProviderDTO started...");

        checkSystemRequest(provider.getProvider(), origin, true);

        if (provider.getServiceInterfaces() == null || provider.getServiceInterfaces().isEmpty()) {
            throw new Exception("Service interface list is null or empty");
        }

        for (final String intf : provider.getServiceInterfaces()) {
            if (!interfaceNameVerifier.isValid(intf)) {
                throw new Exception("Specified interface name is not valid: " + intf);
            }
        }

        if (provider.getTokenDuration() <= 0) {
            provider.setTokenDuration(-1);
        }
    }
    
}
