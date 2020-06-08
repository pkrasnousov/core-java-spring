package eu.arrowhead.core.authorization.protocols.coap;

import com.fasterxml.jackson.databind.ObjectMapper;
import javax.annotation.PostConstruct;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import eu.arrowhead.common.CommonConstants;
import eu.arrowhead.common.CoreCommonConstants;
import eu.arrowhead.common.Utilities;
import eu.arrowhead.common.coap.AhCoapServer;
import eu.arrowhead.common.coap.configuration.CoapCertificates;
import eu.arrowhead.common.coap.configuration.CoapCredentials;
import eu.arrowhead.common.coap.configuration.CoapServerConfiguration;
import eu.arrowhead.common.coap.tools.CoapTools;

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
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.springframework.beans.factory.annotation.Autowired;

@Component
public class CoapAuthorization {

    //=================================================================================================
    // members    
    private final Logger logger = LogManager.getLogger(CoapAuthorization.class);
    private AhCoapServer coapServer;

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

    private final String URL_PATH_ECHO = "echo";
    private final String URL_PATH_INTERCLOUD = "intercloud";
    private final String URL_PATH_INTRACLOUD = "intracloud";
    private final String URL_PATH_PUBLICKEY = "publickey";
    private final String URL_PATH_TOKEN = "token";
    private final String URL_PATH_SUBSCRIPTION = "subscription";
    private final String URL_PATH_CHECK = "check";

    //=================================================================================================
    // methods
    //-------------------------------------------------------------------------------------------------
    @PostConstruct
    public void init() {
        logger.info("\n\nCOAP SERVER\n\n");
        logger.info(",...");
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
        coapServer.add(new IntercloudResource());
        coapServer.add(new IntracloudResource());
        coapServer.add(new PublickeyResource());
        coapServer.add(new TokenResource());
        coapServer.add(new SubscriptionResource());
    }

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

    //=================================================================================================
    // CoAP resources
    //-------------------------------------------------------------------------------------------------
    class EchoResource extends CoapResource {

        public EchoResource() {
            super(URL_PATH_ECHO);
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
    class IntercloudResource extends CoapResource {

        public IntercloudResource() {
            super(URL_PATH_INTERCLOUD);
            setVisible(false);
            add(new IntercloudCheckResource());
        }

    }

    //-------------------------------------------------------------------------------------------------
    class IntercloudCheckResource extends CoapResource {

        private final ObjectMapper mapper = new ObjectMapper();

        public IntercloudCheckResource() {
            super(URL_PATH_CHECK);
            getAttributes().setTitle("Intercloud Check Resource");
        }

        @Override
        public void handlePOST(CoapExchange exchange) {
            try {
                logger.debug("New AuthorizationInterCloud check request recieved");
                AuthorizationInterCloudCheckRequestDTO request = mapper.readValue(exchange.getRequestText(), AuthorizationInterCloudCheckRequestDTO.class);

                final boolean isCloudInvalid = request.getCloud() == null;
                final boolean isCloudOperatorInvalid = isCloudInvalid || Utilities.isEmpty(request.getCloud().getOperator());
                final boolean isCloudNameInvalid = isCloudInvalid || Utilities.isEmpty(request.getCloud().getName());
                final boolean isServiceDefinitionInvalid = Utilities.isEmpty(request.getServiceDefinition());
                final boolean isProvidersWithInterfacesListInvalid = request.getProviderIdsWithInterfaceIds() == null || request.getProviderIdsWithInterfaceIds().isEmpty();

                if (isCloudOperatorInvalid || isCloudNameInvalid || isServiceDefinitionInvalid || isProvidersWithInterfacesListInvalid) {
                    String exceptionMsg = "Payload is invalid due to the following reasons:";
                    exceptionMsg = isCloudOperatorInvalid ? exceptionMsg + " cloud operator is empty, " : exceptionMsg;
                    exceptionMsg = isCloudNameInvalid ? exceptionMsg + " cloud name is empty, " : exceptionMsg;
                    exceptionMsg = isServiceDefinitionInvalid ? exceptionMsg + " serviceDefinition is empty, " : exceptionMsg;
                    exceptionMsg = isProvidersWithInterfacesListInvalid ? exceptionMsg + " invalid providerIdsWithInterfaceIds list," : exceptionMsg;
                    exceptionMsg = exceptionMsg.substring(0, exceptionMsg.length() - 1);

                    throw new Exception(exceptionMsg);
                }

                exchange.respond(
                        CoAP.ResponseCode.CONTENT,
                        mapper.writeValueAsString(authorizationDBService.checkAuthorizationInterCloudResponse(request.getCloud().getOperator(), request.getCloud().getName(),
                                request.getServiceDefinition(), request.getProviderIdsWithInterfaceIds())),
                        MediaTypeRegistry.APPLICATION_JSON);

            } catch (Exception ex) {
                exchange.respond(
                        CoAP.ResponseCode.INTERNAL_SERVER_ERROR,
                        ex.getMessage(),
                        MediaTypeRegistry.TEXT_PLAIN);
            }
        }

    }

    //-------------------------------------------------------------------------------------------------
    class IntracloudResource extends CoapResource {

        public IntracloudResource() {
            super(URL_PATH_INTRACLOUD);
            setVisible(false);
            add(new IntracloudCheckResource());
        }

    }

    //-------------------------------------------------------------------------------------------------
    class IntracloudCheckResource extends CoapResource {

        private final ObjectMapper mapper = new ObjectMapper();

        public IntracloudCheckResource() {
            super(URL_PATH_CHECK);
            getAttributes().setTitle("Intra Check Resource");
        }

        @Override
        public void handlePOST(CoapExchange exchange) {
            try {
                logger.debug("New AuthorizationIntraCloud check request recieved");
                AuthorizationIntraCloudCheckRequestDTO request = mapper.readValue(exchange.getRequestText(), AuthorizationIntraCloudCheckRequestDTO.class);

                final String origin = CommonConstants.AUTHORIZATION_URI + CommonConstants.OP_AUTH_INTRA_CHECK_URI;
                final SystemRequestDTO consumer = request.getConsumer();
                if (consumer == null) {
                    throw new Exception("Consumer is null");
                }

                checkSystemRequest(consumer, origin, false);

                final boolean isServiceDefinitionIdInvalid = request.getServiceDefinitionId() == null || request.getServiceDefinitionId() < 1;
                final boolean isProviderListEmpty = request.getProviderIdsWithInterfaceIds() == null || request.getProviderIdsWithInterfaceIds().isEmpty();

                if (isServiceDefinitionIdInvalid || isProviderListEmpty) {
                    String exceptionMsg = "Payload is invalid due to the following reasons:";
                    exceptionMsg = isServiceDefinitionIdInvalid ? exceptionMsg + " invalid serviceDefinition id," : exceptionMsg;
                    exceptionMsg = isProviderListEmpty ? exceptionMsg + " providerId list is empty," : exceptionMsg;
                    exceptionMsg = exceptionMsg.substring(0, exceptionMsg.length() - 1);
                    throw new Exception(exceptionMsg);
                }

                final Set<IdIdListDTO> providerIdsWithInterfaceIdsSet = new HashSet<>();

                final Set<Long> providerIdCheck = new HashSet<>();
                for (final IdIdListDTO providerWithInterfaces : request.getProviderIdsWithInterfaceIds()) {
                    if (providerWithInterfaces.getId() != null && providerWithInterfaces.getId() > 0 && !providerIdCheck.contains(providerWithInterfaces.getId())) {
                        providerIdCheck.add(providerWithInterfaces.getId());

                        final Set<Long> interfaceIdCheck = new HashSet<>();
                        for (final Long interfaceId : providerWithInterfaces.getIdList()) {
                            if (interfaceId != null && interfaceId > 0 && !interfaceIdCheck.contains(interfaceId)) {
                                interfaceIdCheck.add(interfaceId);
                            } else {
                                logger.debug("Invalid or duplicated interface id: {} with provider id: {}", interfaceId, providerWithInterfaces.getId());
                            }
                        }

                        providerWithInterfaces.getIdList().clear();
                        providerWithInterfaces.getIdList().addAll(interfaceIdCheck);
                        providerIdsWithInterfaceIdsSet.add(providerWithInterfaces);
                    } else {
                        logger.debug("Invalid or duplicated provider system id: {}", providerWithInterfaces.getId());
                    }
                }

                exchange.respond(
                        CoAP.ResponseCode.CONTENT,
                        mapper.writeValueAsString(authorizationDBService.checkAuthorizationIntraCloudRequest(consumer.getSystemName(), consumer.getAddress(), consumer.getPort(),
                                request.getServiceDefinitionId(), providerIdsWithInterfaceIdsSet)),
                        MediaTypeRegistry.APPLICATION_JSON);

            } catch (Exception ex) {
                exchange.respond(
                        CoAP.ResponseCode.INTERNAL_SERVER_ERROR,
                        ex.getMessage(),
                        MediaTypeRegistry.TEXT_PLAIN);
            }
        }

    }

    //-------------------------------------------------------------------------------------------------
    class PublickeyResource extends CoapResource {

        private final ObjectMapper mapper = new ObjectMapper();

        public PublickeyResource() {
            super(URL_PATH_PUBLICKEY);
            getAttributes().setTitle("PublicKey Resource");
        }

        @Override
        public void handleGET(CoapExchange exchange) {
            try {
                exchange.respond(
                        CoAP.ResponseCode.CONTENT,
                        mapper.writeValueAsString(acquireAndConvertPublicKey()),
                        MediaTypeRegistry.APPLICATION_JSON);

            } catch (Exception ex) {
                exchange.respond(
                        CoAP.ResponseCode.INTERNAL_SERVER_ERROR,
                        ex.getMessage(),
                        MediaTypeRegistry.TEXT_PLAIN);
            }
        }

    }

    //-------------------------------------------------------------------------------------------------
    class TokenResource extends CoapResource {

        private final ObjectMapper mapper = new ObjectMapper();

        public TokenResource() {
            super(URL_PATH_TOKEN);
            getAttributes().setTitle("PublicKey Resource");
        }

        @Override
        public void handlePOST(CoapExchange exchange) {
            try {
                logger.debug("New token generation request received");
                TokenGenerationRequestDTO request = mapper.readValue(exchange.getRequestText(), TokenGenerationRequestDTO.class);

                checkTokenGenerationRequest(request);

                exchange.respond(
                        CoAP.ResponseCode.CONTENT,
                        mapper.writeValueAsString(tokenGenerationService.generateTokensResponse(request)),
                        MediaTypeRegistry.APPLICATION_JSON);

            } catch (Exception ex) {
                exchange.respond(
                        CoAP.ResponseCode.INTERNAL_SERVER_ERROR,
                        ex.getMessage(),
                        MediaTypeRegistry.TEXT_PLAIN);
            }
        }

    }

    //-------------------------------------------------------------------------------------------------
    class SubscriptionResource extends CoapResource {

        public SubscriptionResource() {
            super(URL_PATH_SUBSCRIPTION);
            setVisible(false);
            add(new SubscriptionCheckResource());
        }

    }

    //-------------------------------------------------------------------------------------------------
    class SubscriptionCheckResource extends CoapResource {

        private final ObjectMapper mapper = new ObjectMapper();

        public SubscriptionCheckResource() {
            super(URL_PATH_CHECK);
            getAttributes().setTitle("Subscription Check Resource");
        }

        @Override
        public void handlePOST(CoapExchange exchange) {
            try {
                logger.debug("New AuthorizationEventHandler check request recieved");
                AuthorizationSubscriptionCheckRequestDTO request = mapper.readValue(exchange.getRequestText(), AuthorizationSubscriptionCheckRequestDTO.class);

                final String origin = CommonConstants.AUTHORIZATION_URI + CommonConstants.OP_AUTH_SUBSCRIPTION_CHECK_URI;
                final SystemRequestDTO consumer = request.getConsumer();
                if (consumer == null) {
                    throw new Exception("Consumer is null");
                }

                checkSystemRequest(consumer, origin, false);

                if (request.getPublishers() != null && !request.getPublishers().isEmpty()) {
                    for (final SystemRequestDTO publisher : request.getPublishers()) {
                        checkSystemRequest(publisher, origin, false);
                    }
                }

                exchange.respond(
                        CoAP.ResponseCode.CONTENT,
                        mapper.writeValueAsString(authorizationDBService.checkAuthorizationSubscriptionRequest(consumer.getSystemName(), consumer.getAddress(), consumer.getPort(),
                                request.getPublishers())),
                        MediaTypeRegistry.APPLICATION_JSON);

            } catch (Exception ex) {
                exchange.respond(
                        CoAP.ResponseCode.INTERNAL_SERVER_ERROR,
                        ex.getMessage(),
                        MediaTypeRegistry.TEXT_PLAIN);
            }
        }

    }
}
