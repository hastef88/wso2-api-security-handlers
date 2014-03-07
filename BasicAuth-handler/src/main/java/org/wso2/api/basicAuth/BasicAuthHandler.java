package org.wso2.api.basicAuth;

import com.sun.jndi.toolkit.ctx.ComponentContext;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.commons.codec.binary.Base64;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.core.axis2.Axis2Sender;
import org.apache.synapse.rest.Handler;
import org.apache.log4j.Logger;
import org.wso2.carbon.core.services.authentication.AuthenticationFailureException;
import org.wso2.carbon.core.services.authentication.AuthenticatorHelper;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.Map;

/**
 * @scr.component name="wso2.api.basicAuth.dscomponent" immediate="true"
 * @scr.reference name="registry.service"
 * interface="org.wso2.carbon.registry.core.service.RegistryService"
 * cardinality="1..1" policy="dynamic" bind="setRegistryService"
 * unbind="unsetRegistryService"
 * @scr.reference name="user.realmservice.default"
 * interface="org.wso2.carbon.user.core.service.RealmService"
 * cardinality="1..1" policy="dynamic" bind="setRealmService"
 * unbind="unsetRealmService"
 */
public class BasicAuthHandler implements Handler {

    static Logger log = Logger.getLogger(BasicAuthHandler.class.getName());

    private static RegistryService registryService;
    private static RealmService realmService;
    private static UserRealm realm;

    private String userName;
    private String password;

    protected void activate(ComponentContext ctxt) {
        try {
            log.debug("API basic auth Handler");
        } catch (Throwable e) {
            log.error("Failed to activate API basic Auth Handler", e);
        }
    }

    protected void setRegistryService(RegistryService registryService) {
        log.debug("Setting Registry service");
        BasicAuthHandler.registryService = registryService;
    }

    protected void unsetRegistryService(RegistryService registryService) {
        log.debug("Unsetting Registry service");
        this.registryService = null;
    }

    protected void setRealmService(RealmService realmService) {
        log.debug("Setting Realm service");
        this.realmService = realmService;
    }

    protected void unsetRealmService(RealmService realmService) {
        log.debug("Unsetting Realm service");
        this.realmService = null;
    }

    public void addProperty(String s, Object o) {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    public Map getProperties() {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    public boolean handleRequest(MessageContext messageContext) {

        org.apache.axis2.context.MessageContext axis2MessageContext
                = ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        Object headers = axis2MessageContext.getProperty(
                org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);

        ConfigurationContext axis2ConfigurationContext = axis2MessageContext.getConfigurationContext();

        int tenantId = MultitenantUtils.getTenantId(axis2ConfigurationContext);
        log.debug("Rest API Basic auth Handler tenant: " + tenantId);

        try {
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
                    String authHeader = (String) headersMap.get("Authorization");
                    String credentials = authHeader.substring(6).trim();
                    if (processSecurity(credentials,tenantId)) {
                        log.debug("User with username : " + userName + " authenticated successfully");
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
                }
            }
            return false;
        } catch (Exception e) {
            log.error("Unable to execute the authentication process : ", e);
            return false;
        }

    }

    public boolean handleResponse(MessageContext messageContext) {
        return true;
    }

    public boolean processSecurity(String credentials, int tenantId) throws UserStoreException, AuthenticationFailureException {

        boolean isAuthenticated = false;

        String decodedCredentials = new String(new Base64().decode(credentials.getBytes()));
        userName = decodedCredentials.split(":")[0];
        password = decodedCredentials.split(":")[1];

        try {
            realm = AuthenticatorHelper.getUserRealm(tenantId, realmService, registryService);
            if (realm == null)
                log.debug("Unable to pick the realm");
        } catch (Exception e) {
            log.error("Error retrieving user realm for authentication. Tenant id " +
                    tenantId + " user name " + userName, e);
            throw new AuthenticationFailureException
                    (AuthenticationFailureException.AuthenticationFailureReason.SYSTEM_ERROR, userName);
        }

        try {
            isAuthenticated = realm.getUserStoreManager().authenticate(userName, password);
        } catch (Exception e) {
            e.printStackTrace();
        }

        if(!isAuthenticated)
            log.info("Unable to authenticate the user with the UserName : " + userName);

        return isAuthenticated;
    }
}
