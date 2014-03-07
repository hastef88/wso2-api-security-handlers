package org.wso2.api.oAuth2;

/**
 * Created with IntelliJ IDEA.
 * User: dinuka
 * Date: 4/4/13
 * Time: 3:46 PM
 * To change this template use File | Settings | File Templates.
 */

import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.axis2.transport.http.HttpTransportProperties;
import org.apache.http.HttpHeaders;
import org.apache.log4j.Logger;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.core.axis2.Axis2Sender;
import org.wso2.carbon.identity.oauth2.stub.OAuth2TokenValidationServiceStub;
import org.wso2.carbon.identity.oauth2.stub.dto.OAuth2TokenValidationRequestDTO;
import org.apache.synapse.ManagedLifecycle;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.rest.AbstractHandler;
//import org.wso2.carbon.identity.oauth2.stub.dto.OAuth2TokenValidationRequestDTO_OAuth2AccessToken;    //IS460

import java.util.Map;

public class OAuth2Handler extends AbstractHandler implements ManagedLifecycle {

    static Logger log = Logger.getLogger(OAuth2Handler.class.getName());


    private String securityHeader = HttpHeaders.AUTHORIZATION;
    private String consumerKeyHeaderSegment = "Bearer";
    private String oauthHeaderSplitter = ",";
    private String consumerKeySegmentDelimiter = " ";
    private String oauth2TokenValidationService = "oauth2TokenValidationService";
    private String identityServerUserName = "identityServerUserName";
    private String identityServerPw = "identityServerPw";

    @Override
    public boolean handleRequest(MessageContext messageContext) {
        try {
            log.debug("Start OAuth2 Handler Authorization");
            ConfigurationContext configCtx = ConfigurationContextFactory.createConfigurationContextFromFileSystem(null, null);
            //Read parameters from axis2.xml
            String identityServerUrl = messageContext.getConfiguration().getAxisConfiguration().getParameter(oauth2TokenValidationService).getValue().toString();
            String username = messageContext.getConfiguration().getAxisConfiguration().getParameter(identityServerUserName).getValue().toString();
            String password = messageContext.getConfiguration().getAxisConfiguration().getParameter(identityServerPw).getValue().toString();

            OAuth2TokenValidationServiceStub stub = new OAuth2TokenValidationServiceStub(configCtx, identityServerUrl);
            ServiceClient client = stub._getServiceClient();
            Options options = client.getOptions();
            HttpTransportProperties.Authenticator authenticator = new HttpTransportProperties.Authenticator();
            authenticator.setUsername(username);
            authenticator.setPassword(password);
            authenticator.setPreemptiveAuthentication(true);

            options.setProperty(HTTPConstants.AUTHENTICATE, authenticator);
            client.setOptions(options);

            OAuth2TokenValidationRequestDTO dto = new OAuth2TokenValidationRequestDTO();
            //OAuth2TokenValidationRequestDTO_OAuth2AccessToken accessToken = new OAuth2TokenValidationRequestDTO_OAuth2AccessToken(); //IS 4.6.0
            //accessToken.setTokenType("bearer"); //IS 4.6.0
            dto.setTokenType("bearer"); //IS 4.5.0

            org.apache.axis2.context.MessageContext axis2MessageContext
                    = ((Axis2MessageContext) messageContext).getAxis2MessageContext();
            Object headers = axis2MessageContext.getProperty(
                    org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
            if (headers != null && headers instanceof Map) {
                Map headersMap = (Map) headers;

                if (headersMap.get("Authorization") == null) {
                    headersMap.clear();
                    axis2MessageContext.setProperty("HTTP_SC", "401");
                    headersMap.put("WWW-Authenticate", "Basic realm=\"WSO2 ESB\"");
                    axis2MessageContext.setProperty("NO_ENTITY_BODY", new Boolean("true"));
                    messageContext.setProperty("RESPONSE", "true");
                    messageContext.setTo(null);
                    Axis2Sender.sendBack(messageContext);
                    return false;

                } else {

                    String apiKey = null;
                    if (headers != null) {
                        apiKey = extractCustomerKeyFromAuthHeader(headersMap);
                    }

                    if (apiKey != null) {
                        dto.setAccessToken(apiKey); //IS 4.5.0
                        //accessToken.setIdentifier(apiKey); //IS 4.6.0
                        //org.wso2.carbon.identity.oauth2.stub.dto.OAuth2TokenValidationRequestDTO_OAuth2AccessToken
                        //dto.setAccessToken(accessToken);
                        if(stub.validate(dto).getValid()){
                            return true;
                        } else {
                            headersMap.clear();
                            axis2MessageContext.setProperty("HTTP_SC", "403");
                            axis2MessageContext.setProperty("NO_ENTITY_BODY", new Boolean("true"));
                            messageContext.setProperty("RESPONSE", "true");
                            messageContext.setTo(null);
                            Axis2Sender.sendBack(messageContext);
                            return false;
                        }

                    } else {
                        headersMap.clear();
                        axis2MessageContext.setProperty("HTTP_SC", "403");
                        axis2MessageContext.setProperty("NO_ENTITY_BODY", new Boolean("true"));
                        messageContext.setProperty("RESPONSE", "true");
                        messageContext.setTo(null);
                        Axis2Sender.sendBack(messageContext);
                        return false;
                    }

                }
            }
            return false;
        } catch (Exception e) {
            log.error("Error while validating OAuth2 request",e);
            return false;
        }
    }

    public String extractCustomerKeyFromAuthHeader(Map headersMap) {

        //From 1.0.7 version of this component onwards remove the OAuth authorization header from
        // the message is configurable. So we dont need to remove headers at this point.
        String authHeader = (String) headersMap.get(securityHeader);
        if (authHeader == null) {
            return null;
        }

        if (authHeader.startsWith("OAuth ") || authHeader.startsWith("oauth ")) {
            authHeader = authHeader.substring(authHeader.indexOf("o"));
        }

        String[] headers = authHeader.split(oauthHeaderSplitter);
        if (headers != null) {
            for (int i = 0; i < headers.length; i++) {
                String[] elements = headers[i].split(consumerKeySegmentDelimiter);
                if (elements != null && elements.length > 1) {
                    int j = 0;
                    boolean isConsumerKeyHeaderAvailable = false;
                    for (String element : elements) {
                        if (!"".equals(element.trim())) {
                            if (consumerKeyHeaderSegment.equals(elements[j].trim())) {
                                isConsumerKeyHeaderAvailable = true;
                            } else if (isConsumerKeyHeaderAvailable) {
                                return removeLeadingAndTrailing(elements[j].trim());
                            }
                        }
                        j++;
                    }
                }
            }
        }
        return null;
    }

    private String removeLeadingAndTrailing(String base) {
        String result = base;

        if (base.startsWith("\"") || base.endsWith("\"")) {
            result = base.replace("\"", "");
        }
        return result.trim();
    }

    @Override
    public boolean handleResponse(MessageContext messageContext) {
        return true;
    }

    @Override
    public void init(SynapseEnvironment synapseEnvironment) {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    @Override
    public void destroy() {
        //To change body of implemented methods use File | Settings | File Templates.
    }
}
