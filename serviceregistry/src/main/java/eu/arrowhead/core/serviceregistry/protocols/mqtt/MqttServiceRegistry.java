package eu.arrowhead.core.serviceregistry.protocols.mqtt;

import com.fasterxml.jackson.databind.ObjectMapper;

import eu.arrowhead.common.CommonConstants;
import eu.arrowhead.common.CoreDefaults;
import eu.arrowhead.common.CoreCommonConstants;
import eu.arrowhead.common.CoreUtilities;
import eu.arrowhead.common.Utilities;
import eu.arrowhead.common.exception.ArrowheadException;
import eu.arrowhead.common.core.CoreSystemService;
import eu.arrowhead.common.dto.internal.ServiceDefinitionRequestDTO;
import eu.arrowhead.common.dto.shared.ServiceQueryFormDTO;
import eu.arrowhead.common.dto.shared.ServiceRegistryRequestDTO;
import eu.arrowhead.common.dto.shared.ServiceSecurityType;
import eu.arrowhead.common.dto.shared.SystemRequestDTO;
import eu.arrowhead.common.dto.shared.MqttRequestDTO;
import eu.arrowhead.common.dto.shared.MqttResponseDTO;
import eu.arrowhead.core.serviceregistry.database.service.ServiceRegistryDBService;

import java.nio.charset.StandardCharsets;
import java.time.format.DateTimeParseException;
import java.util.Map;
import javax.annotation.PostConstruct;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Sort.Direction;
import org.springframework.stereotype.Component;

import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttCallback;
import org.eclipse.paho.client.mqttv3.IMqttDeliveryToken;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttException;
import org.eclipse.paho.client.mqttv3.MqttMessage;
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence;

@Component
public class MqttServiceRegistry implements MqttCallback, Runnable {

    //=================================================================================================
    // members    
    private final Logger logger = LogManager.getLogger(MqttServiceRegistry.class);

    @Value(CoreCommonConstants.$ORCHESTRATOR_IS_GATEKEEPER_PRESENT_WD)
    private boolean gatekeeperIsPresent;

    @Autowired
    private ServiceRegistryDBService serviceRegistryDBService;

    @Value(CoreCommonConstants.$CORE_SYSTEM_NAME)
    private String mqttSystemName;

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

    Thread t = null;

    //=================================================================================================
    // methods
    //-------------------------------------------------------------------------------------------------
    @PostConstruct
    public void init() {
        logger.info("MQTT protocol");
        if (mqttBrokerEnabled) {
            logger.info("Starting MQTT");

	    t = new Thread(this);
	    t.start();
        }
    }

    MqttClient client = null;
    MemoryPersistence persistence = null;
    private void connectBroker() {

      try {
	MqttConnectOptions connOpts = new MqttConnectOptions();
	connOpts.setCleanSession(true);

	client.setCallback(this);
	client.connect(connOpts);
	String topics[] = {"ah/serviceregistry/echo", "ah/serviceregistry/register", "ah/serviceregistry/unregister", "ah/serviceregistry/query"};
	client.subscribe(topics);
      } catch(MqttException mex) {
	  logger.info("Could no connect to MQTT broker!\n\t" + mex.toString());
      }
    
    }

    @Override
    public void run() {
      while(true) {
	try {
	  if (client == null) {
	    persistence = new MemoryPersistence();
	    client = new MqttClient(mqttBrokerAddress, mqttSystemName, persistence);
	  }
	  if (!client.isConnected()) {
	    connectBroker();
	  }
          Thread.sleep(1000 * 15);
	} catch(InterruptedException iex) {
	  logger.info("Error starting MQTT timeout thread");
	} catch(MqttException mex) {
	  logger.info("MQTT error: " + mex.toString());
	}
      }
    
    }

    @Override
    public void connectionLost(Throwable cause) {
        logger.info("Connection lost to MQTT broker");
	client = null;
    }
    
    @Override
    public void messageArrived(String topic, MqttMessage message) {
      MqttRequestDTO request = null;
      MqttResponseDTO response= null;

      try {
	request = Utilities.fromJson(message.toString(), MqttRequestDTO.class);
      } catch (ArrowheadException ae) {
	logger.info("Could not convert MQTT message to REST request!");
	return;
      }

      logger.info(request.toString());

      switch(topic) {
	case "ah/serviceregistry/echo":
	  logger.info(request.getMethod() + " echo(): " + new String(message.getPayload(), StandardCharsets.UTF_8));
	  if (!request.getMethod().toLowerCase().equals("get")) {
	    return;
	  }
	  try {
	    response = new MqttResponseDTO("200", "Got it");
	    MqttMessage resp = new MqttMessage(Utilities.toJson(response).getBytes());
	    resp.setQos(2);
	    client.publish(request.getReplyTo(), resp);
	  } catch (MqttException mex){
	    logger.info("echo(): Couldn't reply " + mex.toString());
	  }
	  break;
	case "ah/serviceregistry/register":
	  logger.info("register(): " + message.toString());
	  if (!request.getMethod().toLowerCase().equals("post")) {
	    return;
	  }
	  
	  break;
	case "ah/serviceregistry/unregister":
	  logger.info("unregister(): " + message.toString());
	  if (!request.getMethod().toLowerCase().equals("post")) {
	    return;
	  }
	  break;
	case "ah/serviceregistry/query":
	  logger.info("query(): " + message.toString());
	  if (!request.getMethod().toLowerCase().equals("get")) {
	    return;
	  }
	  break;
	default:
	  logger.info("Received message to unsupported topic");
      }
    }

    @Override
    public void deliveryComplete(IMqttDeliveryToken token) {
    
    }

    /* /echo - GET 
    exchange.respond(
                    ResponseCode.CONTENT,
                    "Got it!",
                    MediaTypeRegistry.TEXT_PLAIN);
    */

    /* /services - GET 
    
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
    
     */
 /* /services - POST 
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
     */
    
    /* /services/{id} - GET 
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
    */
    
    /* /services/{id} - PUT 
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
    */
    
    /* /services/{id} - DELETE 
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
    */
    
    /* /register - POST 
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
    */
    
    /* /unregister - DELETE 
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
    */
    
    /* /query - POST 
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
    */
    
    /* /query/all - GET 
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
    */
    
    /* /query/system - POST 
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
    */
    
    /* /query/system/{common_field_name_id} - GET 
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
    */
}
