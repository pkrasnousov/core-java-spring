package eu.arrowhead.core.serviceregistry.protocols.coap;

import com.fasterxml.jackson.databind.ObjectMapper;

import eu.arrowhead.common.CommonConstants;
import eu.arrowhead.common.CoreDefaults;
import eu.arrowhead.common.CoreCommonConstants;
import eu.arrowhead.common.CoreUtilities;
import eu.arrowhead.common.Utilities;
import eu.arrowhead.common.coap.AhCoapServer;
import eu.arrowhead.common.coap.configuration.CoapCertificates;
import eu.arrowhead.common.coap.configuration.CoapCredentials;
import eu.arrowhead.common.coap.configuration.CoapServerConfiguration;
import eu.arrowhead.common.coap.tools.CoapTools;
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
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Sort.Direction;
import org.springframework.stereotype.Component;

@Component
public class CoapServiceRegistry {

    //=================================================================================================
    // members    
    private final Logger logger = LogManager.getLogger(CoapServiceRegistry.class);
    private AhCoapServer coapServer;

    @Value(CoreCommonConstants.$ORCHESTRATOR_IS_GATEKEEPER_PRESENT_WD)
    private boolean gatekeeperIsPresent;

    @Autowired
    private ServiceRegistryDBService serviceRegistryDBService;

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

    final String DIRECTION_KEY = "direction";
    final String DIRECTION_DEFAULT = CoreDefaults.DEFAULT_REQUEST_PARAM_DIRECTION_VALUE;
    final String NULL_DEFAULT = null;
    final String PAGE_KEY = "page";
    final int PAGE_DEFAULT = -1;
    final String ID_KEY = "id";
    final int ID_DEFAULT = 0;
    final String SIZE_KEY = "size";
    final int SIZE_DEFAULT = -1;
    final String SORT_KEY = "sortField";
    final String SORT_DEFAULT = CoreCommonConstants.COMMON_FIELD_NAME_ID;
    final String UNREGISTER_SERVICE_DEFINITION_KEY = "service_definition";
    final String UNREGISTER_SERVICE_PROVIDER_ADDRESS_KEY = "address";
    final String UNREGISTER_SERVICE_PROVIDER_PORT_KEY = "port";
    final String UNREGISTER_SERVICE_PROVIDER_SYSTEM_NAME_KEY = "system_name";

    final String URL_PATH_ALL = "all";
    final String URL_PATH_GROUPED = "grouped";
    final String URL_PATH_ID = "id";
    final String URL_PATH_MGMT = "mgmt";
    final String URL_PATH_QUERY = "query";
    final String URL_PATH_REGISTER = "register";
    final String URL_PATH_SERVICE_DEFINITION = "servicedef";
    final String URL_PATH_SERVICES = "services";
    final String URL_PATH_SYSTEM = "system";
    final String URL_PATH_SYSTEMS = "systems";
    final String URL_PATH_UNREGISTER = "unregister";

    //=================================================================================================
    // methods
    //-------------------------------------------------------------------------------------------------
    @PostConstruct
    public void init() {
        logger.info("CoAP Protocol Init");

        /* Starting CoAP Server (if needed) */
        if (coapServerEnabled) {
            logger.info("CoAP Protocol Enabled");
            CoapServerConfiguration coapServerConfiguration = new CoapServerConfiguration(
                    coapServerAddress,
                    coapServerPort,
                    serverSslEnabled,
                    new CoapCredentials(
                            keyStorePath,
                            keyStorePassword,
                            keyPassword,
                            "serviceregistry-coap"
                    ),
                    new CoapCertificates(
                            "coap-root",
                            trustStorePassword,
                            trustStorePath
                    )
            );
            coapServer = new AhCoapServer(coapServerConfiguration);
            initializateResources(serviceRegistryDBService);
            coapServer.start();
        } else {
            logger.info("CoAP Protocol Disabled");
        }
    }

    //=================================================================================================
    // assistant methods
    //-------------------------------------------------------------------------------------------------//-------------------------------------------------------------------------------------------------
    private void initializateResources(ServiceRegistryDBService serviceRegistryDBService) {
        coapServer.add(new EchoResource());
        //coapServer.add(new ManagementResource(serviceRegistryDBService));
        coapServer.add(new ServicesResource(serviceRegistryDBService));
        coapServer.add(new RegisterResource(serviceRegistryDBService));
        coapServer.add(new UnregisterResource(serviceRegistryDBService));
        coapServer.add(new QueryResource(serviceRegistryDBService));
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
                    ResponseCode.CONTENT,
                    "Got it!",
                    MediaTypeRegistry.TEXT_PLAIN);
        }

    }

    //-------------------------------------------------------------------------------------------------
    // Comment: keep this code in case the management is required in the future.
    /* class ManagementResource extends CoapResource {


        private final ServiceRegistryDBService serviceRegistryDBService;
        private final ObjectMapper mapper = new ObjectMapper();

        public ManagementResource(ServiceRegistryDBService serviceRegistryDBService) {
            super(URL_PATH_MGMT);
            this.serviceRegistryDBService = serviceRegistryDBService;
            add(new ManagementIdResource(serviceRegistryDBService));
            add(new ManagementGroupedResource(serviceRegistryDBService));
            add(new ManagementServiceDefResource(serviceRegistryDBService));
            add(new ManagementSystemsResource(serviceRegistryDBService));
            getAttributes().setTitle("Management Resource");
        }

        @Override
        public void handleGET(CoapExchange exchange) {
            try {
                Map<String, String> queries = CoapTools.getQueryParams(exchange);

                if ((!queries.containsKey(PAGE_KEY) && queries.containsKey(SIZE_KEY))
                        || (queries.containsKey(PAGE_KEY) && !queries.containsKey(SIZE_KEY))) {
                    throw new Exception("Not valid Parameters");
                }

                int validatedPage = CoapTools.getParam(queries, PAGE_KEY, PAGE_DEFAULT);
                int validatedSize = CoapTools.getParam(queries, SIZE_KEY, SIZE_DEFAULT);
                String direction = CoapTools.getParam(queries, DIRECTION_KEY, DIRECTION_DEFAULT);
                String sortField = CoapTools.getParam(queries, SIZE_KEY, SORT_DEFAULT);
                Direction validatedDirection = CoreUtilities.calculateDirection(direction, URL_PATH_MGMT);

                exchange.respond(
                        ResponseCode.CONTENT,
                        mapper.writeValueAsString(serviceRegistryDBService.getServiceRegistryEntriesResponse(validatedPage, validatedSize, validatedDirection, sortField)),
                        MediaTypeRegistry.APPLICATION_JSON);
            } catch (Exception ex) {
                exchange.respond(
                        ResponseCode.INTERNAL_SERVER_ERROR,
                        ex.getMessage(),
                        MediaTypeRegistry.TEXT_PLAIN);
            }
        }

        @Override
        public void handlePOST(CoapExchange exchange) {
            try {
                ServiceRegistryRequestDTO serviceRegistryRequestDTO = mapper.readValue(exchange.getRequestText(), ServiceRegistryRequestDTO.class);
                exchange.respond(
                        ResponseCode.CONTENT,
                        mapper.writeValueAsString(serviceRegistryDBService.registerServiceResponse(serviceRegistryRequestDTO)),
                        MediaTypeRegistry.APPLICATION_JSON);
            } catch (Exception ex) {
                exchange.respond(
                        ResponseCode.INTERNAL_SERVER_ERROR,
                        ex.getMessage(),
                        MediaTypeRegistry.TEXT_PLAIN);
            }
        }

    }

    //-------------------------------------------------------------------------------------------------
    class ManagementIdResource extends CoapResource {

        private final ServiceRegistryDBService serviceRegistryDBService;
        private final ObjectMapper mapper = new ObjectMapper();

        public ManagementIdResource(ServiceRegistryDBService serviceRegistryDBService) {
            super(URL_PATH_ID);
            this.serviceRegistryDBService = serviceRegistryDBService;
            getAttributes().setTitle("Management Id Resource");
        }

        @Override
        public Resource getChild(String name) {
            return this;
        }

        @Override
        public void handleGET(CoapExchange exchange) {
            try {
                long id = Long.parseLong(CoapTools.getUrlPathValue(exchange, URL_PATH_ID));

                if (id < 1) {
                    throw new Exception("Id not valid");
                }

                exchange.respond(
                        ResponseCode.CONTENT,
                        mapper.writeValueAsString(serviceRegistryDBService.getServiceRegistryEntryByIdResponse(id)),
                        MediaTypeRegistry.APPLICATION_JSON);
            } catch (Exception ex) {
                exchange.respond(
                        ResponseCode.INTERNAL_SERVER_ERROR,
                        ex.getMessage(),
                        MediaTypeRegistry.TEXT_PLAIN);
            }
        }

        @Override
        public void handlePUT(CoapExchange exchange) {
            try {
                long id = Long.parseLong(CoapTools.getUrlPathValue(exchange, URL_PATH_ID));

                if (id < 1) {
                    throw new Exception("Id not valid");
                }

                ServiceRegistryRequestDTO serviceRegistryRequestDTO = mapper.readValue(exchange.getRequestText(), ServiceRegistryRequestDTO.class);

                exchange.respond(
                        ResponseCode.CONTENT,
                        mapper.writeValueAsString(serviceRegistryDBService.updateServiceByIdResponse(id, serviceRegistryRequestDTO)),
                        MediaTypeRegistry.APPLICATION_JSON);
            } catch (Exception ex) {
                exchange.respond(
                        ResponseCode.INTERNAL_SERVER_ERROR,
                        ex.getMessage(),
                        MediaTypeRegistry.TEXT_PLAIN);
            }
        }

        @Override
        public void handlePATCH(CoapExchange exchange) {
            try {
                long id = Long.parseLong(CoapTools.getUrlPathValue(exchange, URL_PATH_ID));

                if (id < 1) {
                    throw new Exception("Id not valid");
                }

                ServiceRegistryRequestDTO serviceRegistryRequestDTO = mapper.readValue(exchange.getRequestText(), ServiceRegistryRequestDTO.class);

                exchange.respond(
                        ResponseCode.CONTENT,
                        mapper.writeValueAsString(serviceRegistryDBService.mergeServiceByIdResponse(id, serviceRegistryRequestDTO)),
                        MediaTypeRegistry.APPLICATION_JSON);
            } catch (Exception ex) {
                exchange.respond(
                        ResponseCode.INTERNAL_SERVER_ERROR,
                        ex.getMessage(),
                        MediaTypeRegistry.TEXT_PLAIN);
            }
        }

        @Override
        public void handleDELETE(CoapExchange exchange) {
            try {
                long id = Long.parseLong(CoapTools.getUrlPathValue(exchange, URL_PATH_ID));

                if (id < 1) {
                    throw new Exception("Id not valid");
                }
                serviceRegistryDBService.removeServiceRegistryEntryById(id);
                exchange.respond(ResponseCode.VALID);
            } catch (Exception ex) {
                exchange.respond(
                        ResponseCode.INTERNAL_SERVER_ERROR,
                        ex.getMessage(),
                        MediaTypeRegistry.TEXT_PLAIN);
            }
        }

    }

    //-------------------------------------------------------------------------------------------------
    class ManagementGroupedResource extends CoapResource {

        private final ServiceRegistryDBService serviceRegistryDBService;
        private final ObjectMapper mapper = new ObjectMapper();

        public ManagementGroupedResource(ServiceRegistryDBService serviceRegistryDBService) {
            super(URL_PATH_GROUPED);
            this.serviceRegistryDBService = serviceRegistryDBService;
            getAttributes().setTitle("Management Grouped Resource");
        }

        @Override
        public void handleGET(CoapExchange exchange) {
            try {
                exchange.respond(
                        ResponseCode.CONTENT,
                        mapper.writeValueAsString(serviceRegistryDBService.getServiceRegistryDataForServiceRegistryGroupedResponse()),
                        MediaTypeRegistry.APPLICATION_JSON);
            } catch (Exception ex) {
                exchange.respond(
                        ResponseCode.INTERNAL_SERVER_ERROR,
                        ex.getMessage(),
                        MediaTypeRegistry.TEXT_PLAIN);
            }
        }

    }

    //-------------------------------------------------------------------------------------------------
    class ManagementServiceDefResource extends CoapResource {

        private final ServiceRegistryDBService serviceRegistryDBService;
        private final ObjectMapper mapper = new ObjectMapper();

        public ManagementServiceDefResource(ServiceRegistryDBService serviceRegistryDBService) {
            super(URL_PATH_SERVICE_DEFINITION);
            this.serviceRegistryDBService = serviceRegistryDBService;
            getAttributes().setTitle("Management Service Definition Resource");
        }

        @Override
        public Resource getChild(String name) {
            return this;
        }

        @Override
        public void handleGET(CoapExchange exchange) {
            try {
                Map<String, String> queries = CoapTools.getQueryParams(exchange);

                if ((!queries.containsKey(PAGE_KEY) && queries.containsKey(SIZE_KEY))
                        || (queries.containsKey(PAGE_KEY) && !queries.containsKey(SIZE_KEY))) {
                    throw new Exception("Not valid Parameters");
                }

                int validatedPage = CoapTools.getParam(queries, PAGE_KEY, PAGE_DEFAULT);
                int validatedSize = CoapTools.getParam(queries, SIZE_KEY, SIZE_DEFAULT);
                String direction = CoapTools.getParam(queries, DIRECTION_KEY, DIRECTION_DEFAULT);
                String sortField = CoapTools.getParam(queries, SIZE_KEY, SORT_DEFAULT);
                Direction validatedDirection = CoreUtilities.calculateDirection(direction, URL_PATH_MGMT + "/" + URL_PATH_SERVICE_DEFINITION);

                String serviceDefinition = CoapTools.getUrlPathValue(exchange, URL_PATH_SERVICE_DEFINITION);

                exchange.respond(
                        ResponseCode.CONTENT,
                        mapper.writeValueAsString(serviceRegistryDBService.getServiceRegistryEntriesByServiceDefinitionResponse(serviceDefinition, validatedPage, validatedSize, validatedDirection, sortField)),
                        MediaTypeRegistry.APPLICATION_JSON);
            } catch (Exception ex) {
                exchange.respond(
                        ResponseCode.INTERNAL_SERVER_ERROR,
                        ex.getMessage(),
                        MediaTypeRegistry.TEXT_PLAIN);
            }
        }

    }

    //-------------------------------------------------------------------------------------------------
    class ManagementSystemsResource extends CoapResource {

        private final ServiceRegistryDBService serviceRegistryDBService;
        private final ObjectMapper mapper = new ObjectMapper();

        public ManagementSystemsResource(ServiceRegistryDBService serviceRegistryDBService) {
            super(URL_PATH_SYSTEMS);
            this.serviceRegistryDBService = serviceRegistryDBService;
            add(new ManagementSystemsIdResource(serviceRegistryDBService));
            getAttributes().setTitle("Management Systems Resource");
        }

        @Override
        public void handleGET(CoapExchange exchange) {
            try {
                Map<String, String> queries = CoapTools.getQueryParams(exchange);

                if ((!queries.containsKey(PAGE_KEY) && queries.containsKey(SIZE_KEY))
                        || (queries.containsKey(PAGE_KEY) && !queries.containsKey(SIZE_KEY))) {
                    throw new Exception("Not valid Parameters");
                }

                int validatedPage = CoapTools.getParam(queries, PAGE_KEY, PAGE_DEFAULT);
                int validatedSize = CoapTools.getParam(queries, SIZE_KEY, SIZE_DEFAULT);
                String direction = CoapTools.getParam(queries, DIRECTION_KEY, DIRECTION_DEFAULT);
                String sortField = CoapTools.getParam(queries, SIZE_KEY, SORT_DEFAULT);
                Direction validatedDirection = CoreUtilities.calculateDirection(direction, URL_PATH_MGMT + "/" + URL_PATH_SYSTEMS);

                exchange.respond(
                        ResponseCode.CONTENT,
                        mapper.writeValueAsString(serviceRegistryDBService.getSystemEntries(validatedPage, validatedSize, validatedDirection, sortField)),
                        MediaTypeRegistry.APPLICATION_JSON);
            } catch (Exception ex) {
                exchange.respond(
                        ResponseCode.INTERNAL_SERVER_ERROR,
                        ex.getMessage(),
                        MediaTypeRegistry.TEXT_PLAIN);
            }
        }

        @Override
        public void handlePOST(CoapExchange exchange) {
            try {
                SystemRequestDTO systemRequestDTO = mapper.readValue(exchange.getRequestText(), SystemRequestDTO.class);
                String systemName = systemRequestDTO.getSystemName();
                String address = systemRequestDTO.getAddress();
                int port = systemRequestDTO.getPort();
                String authenticationInfo = systemRequestDTO.getAuthenticationInfo();

                exchange.respond(
                        ResponseCode.CONTENT,
                        mapper.writeValueAsBytes(serviceRegistryDBService.createSystemResponse(systemName, address, port, authenticationInfo)),
                        MediaTypeRegistry.APPLICATION_JSON);
            } catch (Exception ex) {
                exchange.respond(
                        ResponseCode.INTERNAL_SERVER_ERROR,
                        ex.getMessage(),
                        MediaTypeRegistry.TEXT_PLAIN);
            }
        }

    }

    //-------------------------------------------------------------------------------------------------
    class ManagementSystemsIdResource extends CoapResource {

        private final ServiceRegistryDBService serviceRegistryDBService;
        private final ObjectMapper mapper = new ObjectMapper();

        public ManagementSystemsIdResource(ServiceRegistryDBService serviceRegistryDBService) {
            super(URL_PATH_ID);
            this.serviceRegistryDBService = serviceRegistryDBService;
            getAttributes().setTitle("Management System Resource");
        }

        @Override
        public Resource getChild(String name) {
            return this;
        }

        @Override
        public void handleGET(CoapExchange exchange) {
            try {
                int systemId = Integer.parseInt(CoapTools.getUrlPathValue(exchange, URL_PATH_ID));

                if (systemId < 1) {
                    throw new Exception(String.format("Id %d not valid!", systemId));
                }

                exchange.respond(
                        ResponseCode.CONTENT,
                        mapper.writeValueAsString(serviceRegistryDBService.getSystemById(systemId)),
                        MediaTypeRegistry.APPLICATION_JSON);
            } catch (Exception ex) {
                exchange.respond(
                        ResponseCode.INTERNAL_SERVER_ERROR,
                        ex.getMessage(),
                        MediaTypeRegistry.TEXT_PLAIN);
            }
        }

        @Override
        public void handlePUT(CoapExchange exchange) {
            try {
                int systemId = Integer.parseInt(CoapTools.getUrlPathValue(exchange, URL_PATH_ID));
                SystemRequestDTO systemRequestDTO = mapper.readValue(exchange.getRequestText(), SystemRequestDTO.class);
                String validatedSystemName = systemRequestDTO.getSystemName().toLowerCase();
                String validatedAddress = systemRequestDTO.getAddress().toLowerCase();
                int validatedPort = systemRequestDTO.getPort();
                String validatedAuthenticationInfo = systemRequestDTO.getAuthenticationInfo();
                exchange.respond(
                        ResponseCode.CONTENT,
                        mapper.writeValueAsString(serviceRegistryDBService.updateSystemResponse(systemId, validatedSystemName, validatedAddress, validatedPort, validatedAuthenticationInfo)),
                        MediaTypeRegistry.APPLICATION_JSON);
            } catch (Exception ex) {
                exchange.respond(
                        ResponseCode.INTERNAL_SERVER_ERROR,
                        ex.getMessage(),
                        MediaTypeRegistry.TEXT_PLAIN);
            }
        }

        @Override
        public void handlePATCH(CoapExchange exchange) {
            try {
                int systemId = Integer.parseInt(CoapTools.getUrlPathValue(exchange, URL_PATH_ID));
                SystemRequestDTO systemRequestDTO = mapper.readValue(exchange.getRequestText(), SystemRequestDTO.class);
                String validatedSystemName = systemRequestDTO.getSystemName().toLowerCase();
                String validatedAddress = systemRequestDTO.getAddress().toLowerCase();
                int validatedPort = systemRequestDTO.getPort();
                String validatedAuthenticationInfo = systemRequestDTO.getAuthenticationInfo();
                exchange.respond(
                        ResponseCode.CONTENT,
                        mapper.writeValueAsString(serviceRegistryDBService.mergeSystemResponse(systemId, validatedSystemName, validatedAddress, validatedPort, validatedAuthenticationInfo)),
                        MediaTypeRegistry.APPLICATION_JSON);
            } catch (Exception ex) {
                exchange.respond(
                        ResponseCode.INTERNAL_SERVER_ERROR,
                        ex.getMessage(),
                        MediaTypeRegistry.TEXT_PLAIN);
            }
        }

        @Override
        public void handleDELETE(CoapExchange exchange) {
            try {

                int systemId = Integer.parseInt(CoapTools.getUrlPathValue(exchange, URL_PATH_ID));

                if (systemId < 1) {
                    throw new Exception(String.format("Id %d not valid!", systemId));
                }

                serviceRegistryDBService.removeSystemById(systemId);
                exchange.respond(ResponseCode.VALID);
            } catch (Exception ex) {
                exchange.respond(
                        ResponseCode.INTERNAL_SERVER_ERROR,
                        ex.getMessage(),
                        MediaTypeRegistry.TEXT_PLAIN);
            }
        }

    }*/
    //-------------------------------------------------------------------------------------------------
    class ServicesResource extends CoapResource {

        private final ServiceRegistryDBService serviceRegistryDBService;
        private final ObjectMapper mapper = new ObjectMapper();

        public ServicesResource(ServiceRegistryDBService serviceRegistryDBService) {
            super(URL_PATH_SERVICES);
            this.serviceRegistryDBService = serviceRegistryDBService;
            add(new ServicesIdResource(serviceRegistryDBService));
            getAttributes().setTitle("Services Resource");
        }

        @Override
        public void handleGET(CoapExchange exchange) {
            try {
                Map<String, String> queries = CoapTools.getQueryParams(exchange);

                if ((!queries.containsKey(PAGE_KEY) && queries.containsKey(SIZE_KEY))
                        || (queries.containsKey(PAGE_KEY) && !queries.containsKey(SIZE_KEY))) {
                    throw new Exception("Not valid Parameters");
                }

                int validatedPage = CoapTools.getParam(queries, PAGE_KEY, PAGE_DEFAULT);
                int validatedSize = CoapTools.getParam(queries, SIZE_KEY, SIZE_DEFAULT);
                String direction = CoapTools.getParam(queries, DIRECTION_KEY, DIRECTION_DEFAULT);
                String sortField = CoapTools.getParam(queries, SIZE_KEY, SORT_DEFAULT);
                Direction validatedDirection = CoreUtilities.calculateDirection(direction, URL_PATH_MGMT + "/" + URL_PATH_SERVICES);

                exchange.respond(
                        ResponseCode.CONTENT,
                        mapper.writeValueAsString(serviceRegistryDBService.getServiceDefinitionEntriesResponse(validatedPage, validatedSize, validatedDirection, sortField)),
                        MediaTypeRegistry.APPLICATION_JSON);
            } catch (Exception ex) {
                exchange.respond(
                        ResponseCode.INTERNAL_SERVER_ERROR,
                        ex.getMessage(),
                        MediaTypeRegistry.TEXT_PLAIN);
            }
        }

        @Override
        public void handlePOST(CoapExchange exchange) {
            try {
                ServiceDefinitionRequestDTO serviceDefinitionRequestDTO = mapper.readValue(exchange.getRequestText(), ServiceDefinitionRequestDTO.class);

                if (Utilities.isEmpty(serviceDefinitionRequestDTO.getServiceDefinition())) {
                    throw new Exception("Service definition is null or blank");
                }

                for (CoreSystemService coreSystemService : CoreSystemService.values()) {
                    if (coreSystemService.getServiceDefinition().equalsIgnoreCase(serviceDefinitionRequestDTO.getServiceDefinition().trim())) {
                        throw new Exception("serviceDefinition '" + serviceDefinitionRequestDTO.getServiceDefinition() + "' is a reserved arrowhead core system service.");
                    }
                }

                exchange.respond(
                        ResponseCode.CONTENT,
                        mapper.writeValueAsBytes(serviceRegistryDBService.createServiceDefinitionResponse(serviceDefinitionRequestDTO.getServiceDefinition())),
                        MediaTypeRegistry.APPLICATION_JSON);
            } catch (Exception ex) {
                exchange.respond(
                        ResponseCode.INTERNAL_SERVER_ERROR,
                        ex.getMessage(),
                        MediaTypeRegistry.TEXT_PLAIN);
            }
        }

    }

    //-------------------------------------------------------------------------------------------------
    class ServicesIdResource extends CoapResource {

        private final ServiceRegistryDBService serviceRegistryDBService;
        private final ObjectMapper mapper = new ObjectMapper();

        public ServicesIdResource(ServiceRegistryDBService serviceRegistryDBService) {
            super(URL_PATH_ID);
            this.serviceRegistryDBService = serviceRegistryDBService;
            getAttributes().setTitle("Services Id Resource");
        }

        @Override
        public Resource getChild(String name) {
            return this;
        }

        @Override
        public void handleGET(CoapExchange exchange) {
            try {
                int serviceId = Integer.parseInt(CoapTools.getUrlPathValue(exchange, URL_PATH_ID));

                if (serviceId < 1) {
                    throw new Exception(String.format("Id %d not valid!", serviceId));
                }

                exchange.respond(
                        ResponseCode.CONTENT,
                        mapper.writeValueAsString(serviceRegistryDBService.getServiceDefinitionByIdResponse(serviceId)),
                        MediaTypeRegistry.APPLICATION_JSON);
            } catch (Exception ex) {
                exchange.respond(
                        ResponseCode.INTERNAL_SERVER_ERROR,
                        ex.getMessage(),
                        MediaTypeRegistry.TEXT_PLAIN);
            }
        }

        @Override
        public void handlePUT(CoapExchange exchange) {
            try {
                int serviceId = Integer.parseInt(CoapTools.getUrlPathValue(exchange, URL_PATH_ID));

                if (serviceId < 1) {
                    throw new Exception(String.format("Id %d not valid!", serviceId));
                }

                ServiceDefinitionRequestDTO serviceDefinitionRequestDTO = mapper.readValue(exchange.getRequestText(), ServiceDefinitionRequestDTO.class);

                if (Utilities.isEmpty(serviceDefinitionRequestDTO.getServiceDefinition())) {
                    throw new Exception("Service definition is null or blank");
                }

                for (CoreSystemService coreSystemService : CoreSystemService.values()) {
                    if (coreSystemService.getServiceDefinition().equalsIgnoreCase(serviceDefinitionRequestDTO.getServiceDefinition().trim())) {
                        throw new Exception("serviceDefinition '" + serviceDefinitionRequestDTO.getServiceDefinition() + "' is a reserved arrowhead core system service.");
                    }
                }

                exchange.respond(
                        ResponseCode.CONTENT,
                        mapper.writeValueAsString(serviceRegistryDBService.updateServiceDefinitionByIdResponse(serviceId, serviceDefinitionRequestDTO.getServiceDefinition())),
                        MediaTypeRegistry.APPLICATION_JSON);
            } catch (Exception ex) {
                exchange.respond(
                        ResponseCode.INTERNAL_SERVER_ERROR,
                        ex.getMessage(),
                        MediaTypeRegistry.TEXT_PLAIN);
            }
        }

        @Override
        public void handleDELETE(CoapExchange exchange) {
            try {
                int serviceId = Integer.parseInt(CoapTools.getUrlPathValue(exchange, URL_PATH_ID));

                if (serviceId < 1) {
                    throw new Exception(String.format("Id %d not valid!", serviceId));
                }
                serviceRegistryDBService.removeServiceDefinitionById(serviceId);
                exchange.respond(ResponseCode.VALID);
            } catch (Exception ex) {
                exchange.respond(
                        ResponseCode.INTERNAL_SERVER_ERROR,
                        ex.getMessage(),
                        MediaTypeRegistry.TEXT_PLAIN);
            }
        }

    }

    //-------------------------------------------------------------------------------------------------
    class RegisterResource extends CoapResource {

        private final ServiceRegistryDBService serviceRegistryDBService;
        private final ObjectMapper mapper = new ObjectMapper();

        public RegisterResource(ServiceRegistryDBService serviceRegistryDBService) {
            super(URL_PATH_REGISTER);
            this.serviceRegistryDBService = serviceRegistryDBService;
            getAttributes().setTitle("Register Resource");
        }

        @Override
        public void handlePOST(CoapExchange exchange) {
            try {

                ServiceRegistryRequestDTO serviceRegistryRequestDTO = mapper.readValue(exchange.getRequestText(), ServiceRegistryRequestDTO.class);
                String origin = URL_PATH_MGMT + "/" + URL_PATH_REGISTER;

                if (Utilities.isEmpty(serviceRegistryRequestDTO.getServiceDefinition())) {
                    throw new Exception("Service definition is null or blank");
                }

                if (!Utilities.isEmpty(serviceRegistryRequestDTO.getEndOfValidity())) {
                    try {
                        Utilities.parseUTCStringToLocalZonedDateTime(serviceRegistryRequestDTO.getEndOfValidity().trim());
                    } catch (final DateTimeParseException ex) {
                        throw new Exception("End of validity is specified in the wrong format. Please provide UTC time using " + Utilities.getDatetimePattern() + " pattern.");
                    }
                }

                ServiceSecurityType securityType = null;
                if (serviceRegistryRequestDTO.getSecure() != null) {
                    for (final ServiceSecurityType type : ServiceSecurityType.values()) {
                        if (type.name().equalsIgnoreCase(serviceRegistryRequestDTO.getSecure())) {
                            securityType = type;
                            break;
                        }
                    }

                    if (securityType == null) {
                        throw new Exception("Security type is not valid.");
                    }
                } else {
                    securityType = ServiceSecurityType.NOT_SECURE;
                }

                if (securityType != ServiceSecurityType.NOT_SECURE && serviceRegistryRequestDTO.getProviderSystem().getAuthenticationInfo() == null) {
                    throw new Exception("Security type is in conflict with the availability of the authentication info.");
                }

                exchange.respond(
                        ResponseCode.CONTENT,
                        mapper.writeValueAsString(serviceRegistryDBService.registerServiceResponse(serviceRegistryRequestDTO)),
                        MediaTypeRegistry.APPLICATION_JSON);
            } catch (Exception ex) {
                exchange.respond(
                        ResponseCode.INTERNAL_SERVER_ERROR,
                        ex.getMessage(),
                        MediaTypeRegistry.TEXT_PLAIN);
            }
        }

    }

    //-------------------------------------------------------------------------------------------------
    class UnregisterResource extends CoapResource {

        private final ServiceRegistryDBService serviceRegistryDBService;
        private final ObjectMapper mapper = new ObjectMapper();

        public UnregisterResource(ServiceRegistryDBService serviceRegistryDBService) {
            super(URL_PATH_UNREGISTER);
            this.serviceRegistryDBService = serviceRegistryDBService;
            getAttributes().setTitle("Unegister Resource");
        }

        @Override
        public void handleDELETE(CoapExchange exchange) {
            try {
                Map<String, String> queries = CoapTools.getQueryParams(exchange);

                String serviceDefinition = CoapTools.getParam(queries, UNREGISTER_SERVICE_DEFINITION_KEY, NULL_DEFAULT);
                String providerName = CoapTools.getParam(queries, UNREGISTER_SERVICE_PROVIDER_SYSTEM_NAME_KEY, NULL_DEFAULT);
                String providerAddress = CoapTools.getParam(queries, UNREGISTER_SERVICE_PROVIDER_ADDRESS_KEY, NULL_DEFAULT);
                int providerPort = CoapTools.getParam(queries, UNREGISTER_SERVICE_PROVIDER_PORT_KEY, 0);

                if (Utilities.isEmpty(serviceDefinition)) {
                    throw new Exception("Service definition is blank");
                }

                if (Utilities.isEmpty(providerName)) {
                    throw new Exception("Name of the provider system is blank");
                }

                if (Utilities.isEmpty(providerAddress)) {
                    throw new Exception("Address of the provider system is blank");
                }

                if (providerPort < CommonConstants.SYSTEM_PORT_RANGE_MIN || providerPort > CommonConstants.SYSTEM_PORT_RANGE_MAX) {
                    throw new Exception("Port must be between " + CommonConstants.SYSTEM_PORT_RANGE_MIN + " and " + CommonConstants.SYSTEM_PORT_RANGE_MAX + ".");
                }
                serviceRegistryDBService.removeServiceRegistry(serviceDefinition, providerName, providerAddress, providerPort);
                exchange.respond(ResponseCode.VALID);
            } catch (Exception ex) {
                exchange.respond(
                        ResponseCode.INTERNAL_SERVER_ERROR,
                        ex.getMessage(),
                        MediaTypeRegistry.TEXT_PLAIN);
            }
        }

    }

    //-------------------------------------------------------------------------------------------------
    class QueryResource extends CoapResource {

        private final ServiceRegistryDBService serviceRegistryDBService;
        private final ObjectMapper mapper = new ObjectMapper();

        public QueryResource(ServiceRegistryDBService serviceRegistryDBService) {
            super(URL_PATH_QUERY);
            this.serviceRegistryDBService = serviceRegistryDBService;
            add(new QueryAllResource(serviceRegistryDBService));
            add(new QuerySystemResource(serviceRegistryDBService));
            getAttributes().setTitle("Query Resource");
        }

        @Override
        public void handlePOST(CoapExchange exchange) {
            try {
                ServiceQueryFormDTO serviceQueryFormDTO = mapper.readValue(exchange.getRequestText(), ServiceQueryFormDTO.class);

                if (Utilities.isEmpty(serviceQueryFormDTO.getServiceDefinitionRequirement())) {
                    throw new Exception("Service definition requirement is null or blank");
                }
                exchange.respond(
                        ResponseCode.CONTENT,
                        mapper.writeValueAsString(serviceRegistryDBService.queryRegistry(serviceQueryFormDTO)),
                        MediaTypeRegistry.APPLICATION_JSON);
            } catch (Exception ex) {
                exchange.respond(
                        ResponseCode.INTERNAL_SERVER_ERROR,
                        ex.getMessage(),
                        MediaTypeRegistry.TEXT_PLAIN);
            }
        }

    }

    //-------------------------------------------------------------------------------------------------
    class QueryAllResource extends CoapResource {

        private final ServiceRegistryDBService serviceRegistryDBService;
        private final ObjectMapper mapper = new ObjectMapper();

        public QueryAllResource(ServiceRegistryDBService serviceRegistryDBService) {
            super(URL_PATH_ALL);
            this.serviceRegistryDBService = serviceRegistryDBService;
            getAttributes().setTitle("Query All Resource");
        }

        @Override
        public void handleGET(CoapExchange exchange) {
            try {
                int page = 0;
                int size = Integer.MAX_VALUE;
                Direction direction = Direction.ASC;
                String sortField = CommonConstants.COMMON_FIELD_NAME_ID;

                exchange.respond(
                        ResponseCode.CONTENT,
                        mapper.writeValueAsString(serviceRegistryDBService.getServiceRegistryEntriesResponse(page, size, direction, sortField)),
                        MediaTypeRegistry.APPLICATION_JSON);
            } catch (Exception ex) {
                exchange.respond(
                        ResponseCode.INTERNAL_SERVER_ERROR,
                        ex.getMessage(),
                        MediaTypeRegistry.TEXT_PLAIN);
            }
        }

    }

    //-------------------------------------------------------------------------------------------------
    class QuerySystemResource extends CoapResource {

        private final ServiceRegistryDBService serviceRegistryDBService;
        private final ObjectMapper mapper = new ObjectMapper();

        public QuerySystemResource(ServiceRegistryDBService serviceRegistryDBService) {
            super(URL_PATH_SYSTEM);
            this.serviceRegistryDBService = serviceRegistryDBService;
            add(new QuerySystemIdResource(serviceRegistryDBService));
            getAttributes().setTitle("Query System Resource");
        }

        @Override
        public void handlePOST(CoapExchange exchange) {
            try {
                SystemRequestDTO systemRequestDTO = mapper.readValue(exchange.getRequestText(), SystemRequestDTO.class);

                if (systemRequestDTO == null) {
                    throw new Exception("System is null.");
                }

                if (Utilities.isEmpty(systemRequestDTO.getSystemName())) {
                    throw new Exception("System Name is null.");
                }

                if (Utilities.isEmpty(systemRequestDTO.getAddress())) {
                    throw new Exception("Empty System Address");
                }

                if (systemRequestDTO.getPort() == null) {
                    throw new Exception("Empty Port");
                }

                final int validatedPort = systemRequestDTO.getPort().intValue();
                if (validatedPort < CommonConstants.SYSTEM_PORT_RANGE_MIN || validatedPort > CommonConstants.SYSTEM_PORT_RANGE_MAX) {
                    throw new Exception("Port must be between " + CommonConstants.SYSTEM_PORT_RANGE_MIN + " and " + CommonConstants.SYSTEM_PORT_RANGE_MAX + ".");
                }

                String systemName = systemRequestDTO.getSystemName();
                String address = systemRequestDTO.getAddress();
                int port = systemRequestDTO.getPort();

                exchange.respond(
                        ResponseCode.CONTENT,
                        mapper.writeValueAsString(serviceRegistryDBService.getSystemByNameAndAddressAndPortResponse(systemName, address, port)),
                        MediaTypeRegistry.APPLICATION_JSON);
            } catch (Exception ex) {
                exchange.respond(
                        ResponseCode.INTERNAL_SERVER_ERROR,
                        ex.getMessage(),
                        MediaTypeRegistry.TEXT_PLAIN);
            }
        }

    }

    //-------------------------------------------------------------------------------------------------
    class QuerySystemIdResource extends CoapResource {

        private final ServiceRegistryDBService serviceRegistryDBService;
        private final ObjectMapper mapper = new ObjectMapper();

        public QuerySystemIdResource(ServiceRegistryDBService serviceRegistryDBService) {
            super(URL_PATH_ID);
            this.serviceRegistryDBService = serviceRegistryDBService;
            getAttributes().setTitle("Query System Id Resource");
        }

        @Override
        public Resource getChild(String name) {
            return this;
        }

        @Override
        public void handleGET(CoapExchange exchange) {
            try {
                int systemId = Integer.parseInt(CoapTools.getUrlPathValue(exchange, URL_PATH_ID));

                if (systemId < 1) {
                    throw new Exception(String.format("Id %d not valid!", systemId));
                }

                exchange.respond(
                        ResponseCode.CONTENT,
                        mapper.writeValueAsString(serviceRegistryDBService.getSystemById(systemId)),
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
