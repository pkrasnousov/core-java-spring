package eu.arrowhead.coapclient.client;

import eu.arrowhead.coapclient.client.configuration.ConfigurationClient;
import eu.arrowhead.coapclient.client.configuration.ConfigurationSecurity;
import eu.arrowhead.coapclient.client.tools.CoapTools;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class ClientCoap {

    private static final Logger LOG = LoggerFactory.getLogger(ClientCoap.class.getName());
    private final ConfigurationClient configuration;
    private final CoapClient coapClient;
    private final String uri;

    ClientCoap(ConfigurationClient configuration) {
        this.configuration = configuration;
        uri = configuration.getUriString();
        coapClient = new CoapClient();
        if (configuration.isSecured()) {
            coapClient.setEndpoint(createSecuredEndPoint(configuration.getSecurityConfiguration()));
        }

    }

    private Endpoint createSecuredEndPoint(ConfigurationSecurity security) {
        DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder();
        builder.setClientOnly();
        builder.setSniEnabled(false);
        builder.setRecommendedCipherSuitesOnly(false);
        
        try {
            SslContextUtil.Credentials serverCredentials = SslContextUtil.loadCredentials(
                    SslContextUtil.CLASSPATH_SCHEME + security.getKeyStoreFile(),
                    security.getClientAlias(),
                    security.getKeyStorePasswordAsCharArray(),
                    security.getKeyStorePasswordAsCharArray());

            Certificate[] trustedCertificates = SslContextUtil.loadTrustedCertificates(
                    SslContextUtil.CLASSPATH_SCHEME + security.getTrustStoreFile(),
                    security.getTrustAlias(),
                    security.getTrustStorePasswordAsCharArray());
            builder.setTrustStore(trustedCertificates);
            builder.setRpkTrustAll();

            List<CertificateType> types = new ArrayList<>();

            types.add(CertificateType.RAW_PUBLIC_KEY);
            types.add(CertificateType.X_509);

            builder.setIdentity(serverCredentials.getPrivateKey(), serverCredentials.getCertificateChain(), types);

        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            System.err.println("certificates are invalid!");
            System.err.println("Therefore certificates are not supported!");
        } catch (IOException e) {
            e.printStackTrace();
            System.err.println("certificates are missing!");
            System.err.println("Therefore certificates are not supported!");
        }

        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());
        CoapEndpoint.Builder coapEndPointBuilder = new CoapEndpoint.Builder();
        coapEndPointBuilder.setConnector(dtlsConnector);
        return coapEndPointBuilder.build();
    }

    public CoapResponse DELETE(String resource) throws ConnectorException, IOException {
        coapClient.setURI(uri + resource);
        LOG.debug("DELETE to " + coapClient.getURI());
        CoapResponse response = coapClient.delete();
        LOG.debug(CoapTools.formatResponse(response));
        return response;
    }

    public CoapResponse GET(String resource) throws ConnectorException, IOException {
        coapClient.setURI(uri + resource);
        LOG.debug("GET to " + coapClient.getURI());
        CoapResponse response = coapClient.get();
        LOG.debug(CoapTools.formatResponse(response));
        return response;
    }
    
    public CoapResponse POST(String resource, String payload, int format) throws ConnectorException, IOException {
        coapClient.setURI(uri + resource);
        LOG.debug("POST to " + coapClient.getURI());
        CoapResponse response = coapClient.post(payload, format);
        LOG.debug(CoapTools.formatResponse(response));
        return response;
    }
    public CoapResponse POST(String resource, String payload, int format, int accept) throws ConnectorException, IOException {
        coapClient.setURI(uri + resource);
        LOG.debug("POST to " + coapClient.getURI());
        CoapResponse response = coapClient.post(payload, format, accept);
        LOG.debug(CoapTools.formatResponse(response));
        return response;
    }
    
    public CoapResponse PUT(String resource, String payload, int format) throws ConnectorException, IOException {
        coapClient.setURI(uri + resource);
        LOG.debug("PUT to " + coapClient.getURI());
        CoapResponse response = coapClient.put(payload, format);
        LOG.debug(CoapTools.formatResponse(response));
        return response;
    }
    
    public CoapResponse PATCH(String resource, String payload, int format) throws ConnectorException, IOException {
        throw new IOException("Method not implemented!");
    }
    
    

}
