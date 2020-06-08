package eu.arrowhead.coapclient;

import java.io.IOException;
import org.apache.log4j.PropertyConfigurator;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Main {

    private static final Logger LOG = LoggerFactory.getLogger(Main.class.getName());

    public static void main(String[] args) throws ConnectorException, IOException {
        PropertyConfigurator.configure(Main.class.getClassLoader().getResourceAsStream("logger.properties"));
        LOG.info("Arrowhead CoAP Client Demo");
        
        ArrowheadCoapClient ahCoapClient = new ArrowheadCoapClient();
        CoapResponse response;
        
        LOG.info(ahCoapClient.getServiceRegistry().getResources());
        //LOG.info(format("Service Registry", "getResources", "", response));
        /*response = ahCoapClient.getServiceRegistry().getEcho();
        LOG.info(format("Service Registry", "getEcho", "", response));
        response = ahCoapClient.getServiceRegistry().getManagementSystemById(1234);
        LOG.info(format("Service Registry", "getManagementSystemById", "1234", response));
        response = ahCoapClient.getServiceRegistry().getManagementSystems();
        LOG.info(format("Service Registry", "getManagementSystems", "", response));
        response = ahCoapClient.getServiceRegistry().getManagementSystems(10,10);
        LOG.info(format("Service Registry", "getManagementSystems", "10,10", response));*/
        
        
        /*response = ahCoapClient.getServiceRegistry().coapGET("echo");
        LOG.info(format("Service Registry", "echo GET", "", response));
        
        response = ahCoapClient.getServiceRegistry().coapGET("mgmt");
        LOG.info(format("Service Registry", "mgmt GET", "", response));
        response = ahCoapClient.getServiceRegistry().coapPOST("mgmt");
        LOG.info(format("Service Registry", "mgmt POST", "", response));
        
        response = ahCoapClient.getServiceRegistry().coapGET("mgmt/id/12343");
        LOG.info(format("Service Registry", "mgmt id GET", "12345", response));
        response = ahCoapClient.getServiceRegistry().coapPUT("mgmt/id/12343");
        LOG.info(format("Service Registry", "mgmt id PUT", "12345", response));
        //response = ahCoapClient.getServiceRegistry().coapPATCH("mgmt/id/12343");
        //LOG.info(format("Service Registry", "mgmt id PATCH", "12345", response));
        response = ahCoapClient.getServiceRegistry().coapDELETE("mgmt/id/12343");
        LOG.info(format("Service Registry", "mgmt id DELETE", "12345", response));
        
        response = ahCoapClient.getServiceRegistry().coapGET("mgmt/grouped");
        LOG.info(format("Service Registry", "mgmt/grouped GET", "", response));
        
        response = ahCoapClient.getServiceRegistry().coapGET("mgmt/servicedef/1234");
        LOG.info(format("Service Registry", "mgmt/servicedef GET", "1234", response));
        
        response = ahCoapClient.getServiceRegistry().coapGET("mgmt/systems");
        LOG.info(format("Service Registry", "mgmt/systems GET", "", response));
        response = ahCoapClient.getServiceRegistry().coapPOST("mgmt/systems");
        LOG.info(format("Service Registry", "mgmt/systems POST", "", response));
        
        response = ahCoapClient.getServiceRegistry().coapGET("mgmt/system/12345");
        LOG.info(format("Service Registry", "mgmt/system GET", "12345", response));
        response = ahCoapClient.getServiceRegistry().coapPUT("mgmt/system/12345");
        LOG.info(format("Service Registry", "mgmt/system PUT", "12345", response));
        //response = ahCoapClient.getServiceRegistry().coapPATCH("mgmt/system/12345");
        //LOG.info(format("Service Registry", "mgmt/system PATCH", "12345", response));
        response = ahCoapClient.getServiceRegistry().coapDELETE("mgmt/system/12345");
        LOG.info(format("Service Registry", "mgmt/system DELETE", "12345", response));
        
        response = ahCoapClient.getServiceRegistry().coapGET("services");
        LOG.info(format("Service Registry", "services GET", "", response));
        response = ahCoapClient.getServiceRegistry().coapPOST("services");
        LOG.info(format("Service Registry", "services POST", "", response));
        
        response = ahCoapClient.getServiceRegistry().coapGET("services/id/1234");
        LOG.info(format("Service Registry", "services/id GET", "123124", response));
        response = ahCoapClient.getServiceRegistry().coapPUT("services/id/1234");
        LOG.info(format("Service Registry", "services/id PUT", "123124", response));
        //response = ahCoapClient.getServiceRegistry().coapPATCH("services/id/1234");
        //LOG.info(format("Service Registry", "services/id PATCH", "123124", response));
        response = ahCoapClient.getServiceRegistry().coapDELETE("services/id/1234");
        LOG.info(format("Service Registry", "services/id DELETE", "123124", response));
        
        response = ahCoapClient.getServiceRegistry().coapPOST("register");
        LOG.info(format("Service Registry", "register POST", "", response));        
        
        response = ahCoapClient.getServiceRegistry().coapDELETE("unregister");
        LOG.info(format("Service Registry", "unregister DELETE", "", response));
        
        response = ahCoapClient.getServiceRegistry().coapPOST("query");
        LOG.info(format("Service Registry", "query POST", "", response));
        
        response = ahCoapClient.getServiceRegistry().coapGET("query/all");
        LOG.info(format("Service Registry", "query/all GET", "", response));
        
        response = ahCoapClient.getServiceRegistry().coapPOST("query/system");
        LOG.info(format("Service Registry", "query/system POST", "", response));
        
        response = ahCoapClient.getServiceRegistry().coapGET("query/system/id/1234");
        LOG.info(format("Service Registry", "query/system/id GET", "1234", response));
        
        
        
        String url = "query/system/id/";
        String resourcePath = "id";
        System.out.println(url);
        int idLen = url.indexOf(resourcePath);
        System.out.println(idLen);
        String tmp = url.substring(idLen+resourcePath.length());
        System.out.println(tmp);
        String[] paths = tmp.split("/");
        String value = (paths.length < 2)? "": paths[1];
        System.out.println("value: "+value);*/
        
        
        //LOG.info(ahCoapClient.getOrchestrator().getResources());
        
        LOG.info(ahCoapClient.getAuthorization().getResources());
        
        response = ahCoapClient.getAuthorization().coapGET("publickey");
        LOG.info(format("Authorization", "publickey", "", response));
        
    }
    
    private static String format(String serviceName, String resource, String request, CoapResponse response) {
        return String.format("%s - %s \nReguest: %s \nResponse[%s]:  %s",
                serviceName,
                resource,
                request,
                response.getCode(),
                response.getResponseText()
                );
    }

}
