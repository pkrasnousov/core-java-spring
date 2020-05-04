package eu.arrowhead.coapclient.client.tools;

import java.security.Principal;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.EndpointContext;

public class CoapTools {

    public static String formatResponse(CoapResponse response) {
        StringBuilder sb = new StringBuilder();
        sb.append("Response:\n\n");
        EndpointContext context = response.advanced().getSourceContext();
        Principal identity = context.getPeerIdentity();
        if (identity != null) {
            sb.append(context.getPeerIdentity()).append("\n");
        } else {
            sb.append("anonymous\n");
        }
        sb.append(context.get(DtlsEndpointContext.KEY_CIPHER)).append("\n");
        sb.append(Utils.prettyPrint(response)).append("\n");
        return sb.toString();
    }
    
}
