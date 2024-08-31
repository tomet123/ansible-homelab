package TODO;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpResponse;
import org.apache.http.client.CookieStore;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.apache.http.util.EntityUtils;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.apache.http.client.CookieStore;
import org.apache.http.cookie.Cookie;
import org.apache.http.cookie.CookieOrigin;
import org.apache.http.cookie.CookieSpec;
import org.apache.http.cookie.CookieSpecProvider;
import org.apache.http.cookie.params.CookieSpecPNames;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.apache.http.impl.cookie.BrowserCompatSpec;
import org.apache.http.impl.cookie.DefaultCookieSpecProvider;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpCoreContext;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.ModelException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.UserModelDelegate;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.idm.model.LDAPObject;
import org.keycloak.storage.ldap.idm.query.Condition;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQuery;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.LDAPOperationDecorator;
import org.keycloak.storage.ldap.mappers.PasswordUpdateCallback;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class LDAPUserAccountControlStorageMapper extends AbstractLDAPStorageMapper implements PasswordUpdateCallback {

    private static final Logger logger = Logger.getLogger(LDAPUserAccountControlStorageMapper.class);

    private final String freeipaApiUrl;
    private final String freeipaUser;
    private final String freeipaPassword;

    private CookieStore cookieStore;

    public LDAPUserAccountControlStorageMapper(ComponentModel mapperModel, LDAPStorageProvider ldapProvider) {
        super(mapperModel, ldapProvider);
        this.freeipaApiUrl = mapperModel.getConfig().getFirst(LDAPUserAccountControlStorageMapperFactory.FREEIPA_API_URL);
        this.freeipaUser = mapperModel.getConfig().getFirst(LDAPUserAccountControlStorageMapperFactory.FREEIPA_USER);
        this.freeipaPassword = mapperModel.getConfig().getFirst(LDAPUserAccountControlStorageMapperFactory.FREEIPA_PASSWORD);
        ldapProvider.setUpdater(this);
    }

    @Override
    public void passwordUpdated(UserModel userModel, LDAPObject ldapObject, UserCredentialModel userCredentialModel) {
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            HttpClientContext context = HttpClientContext.create();
            cookieStore = new BasicCookieStore();
            context.setCookieStore(cookieStore);

            // Step 1: Log in to FreeIPA to get the session cookie
            loginToFreeIPA(client, context);

            String uid = ldapObject.getAttributeAsString("uid");

            // Step 2: Check if the user is disabled
            checkIfUserDisabled(client, context, uid);

            // Step 3: Update the password
            modifyUserPassword(client, context, uid, userCredentialModel.getValue());

            // Step 4: Update password expiration
            updatePasswordExpiration(client, context, uid);

            // Step 5: Reset failed login count
            resetFailedLoginCount(client, context, uid);

            logger.infof("Successfully updated password and account settings for user %s via FreeIPA API.", uid);

        } catch (Exception e) {
            logger.error("Error updating password and account settings via FreeIPA API.", e);
            throw new ModelException("Error updating password and account settings via FreeIPA API.", e);
        }
    }

    private void loginToFreeIPA(CloseableHttpClient client, HttpClientContext context) throws Exception {
        HttpPost loginRequest = new HttpPost(freeipaApiUrl + "/session/login_password");

        // Set up the login payload
        StringEntity loginEntity = new StringEntity("user=" + freeipaUser + "&password=" + freeipaPassword, StandardCharsets.UTF_8);
        loginRequest.setEntity(loginEntity);
        loginRequest.setHeader("Content-Type", "application/x-www-form-urlencoded");
        loginRequest.setHeader("Accept", "text/plain");
        loginRequest.setHeader("referer", freeipaApiUrl);

        HttpResponse response = client.execute(loginRequest, context);
        int statusCode = response.getStatusLine().getStatusCode();
        if (statusCode != 200) {
            throw new ModelException("Failed to log in to FreeIPA. Response code: " + statusCode);
        }

        // Log successful login and store cookies for subsequent requests
        logger.info("Successfully logged in to FreeIPA.");
    }

    private void checkIfUserDisabled(CloseableHttpClient client, HttpClientContext context, String uid) throws Exception {
        // Get user details
        Map<String, Object> userResult = sendFreeIPARequest(client, context, "user_show", List.of(uid),Map.of());

        Map<String, Object> userAttributes = (Map<String, Object>) userResult.get("result");
        if (userAttributes.containsKey("nsaccountlock") && Boolean.TRUE.equals(userAttributes.get("nsaccountlock"))) {
            throw new ModelException("User account is disabled (nsaccountlock is true).");
        }
    }

    private void modifyUserPassword(CloseableHttpClient client, HttpClientContext context, String uid, String newPassword) throws Exception {
        Map<String, String> params = new HashMap<>();
        params.put("password", newPassword);

        sendFreeIPARequest(client, context, "passwd", List.of(uid),params);
    }

    private void updatePasswordExpiration(CloseableHttpClient client, HttpClientContext context, String uid) throws Exception {
        // Log the intention to update the password expiration
        logger.info("Attempting to update password expiration for user: " + uid);

        // Get the password policy details
        Map<String, Object> policyResult = sendFreeIPARequest(client, context, "pwpolicy_show", List.of(), Map.of());

        // Extract the max password life, which is returned as a list of strings
        List<String> krbMaxPwdLifeList = (List<String>) ((Map<String, Object>) policyResult.get("result")).get("krbmaxpwdlife");

        // Check that the list is not empty and contains a valid integer value
        if (krbMaxPwdLifeList != null && !krbMaxPwdLifeList.isEmpty()) {
            int krbMaxPwdLife = Integer.parseInt(krbMaxPwdLifeList.get(0)); // Convert the first element to an int

            // Calculate the new password expiration date
            LocalDateTime now = LocalDateTime.now();
            LocalDateTime expirationDate = now.plusDays(krbMaxPwdLife);
            String formattedExpirationDate = expirationDate.format(DateTimeFormatter.ofPattern("yyyy-MM-dd'Z'"));

            // Prepare the parameters to update the user's password expiration
            Map<String, String> params = new HashMap<>();
            params.put("krbpasswordexpiration", formattedExpirationDate);

            // Send the request to FreeIPA
            Map<String, Object> response = sendFreeIPARequest(client, context, "user_mod", List.of(uid), params);

            // Log the response from FreeIPA
            logger.info("Password expiration update response: " + response);
        } else {
            logger.warn("No valid max password life found in policy for user: " + uid);
        }
    }

    private void resetFailedLoginCount(CloseableHttpClient client, HttpClientContext context, String uid) throws Exception {
        // Get user details
        Map<String, Object> userResult = sendFreeIPARequest(client, context, "user_show",List.of(uid), Map.of());

        Map<String, Object> userAttributes = (Map<String, Object>) userResult.get("result");
        if (userAttributes.containsKey("krbloginfailedcount")) {
            int failedLoginCount = Integer.parseInt(userAttributes.get("krbloginfailedcount").toString());
            if (failedLoginCount > 0) {
                Map<String, String> params = new HashMap<>();
                params.put("setattr", "krbloginfailedcount=0");

                sendFreeIPARequest(client, context, "user_mod", List.of(uid),params);
            }
        }
    }

    private Map<String, Object> sendFreeIPARequest(CloseableHttpClient client, HttpClientContext context, String method, List<String> params,Map<String,String> options) throws Exception {
        HttpPost httpPost = new HttpPost(freeipaApiUrl + "/session/json");


        Map<String, Object> payload = new HashMap<>();
        payload.put("method", method);
        // Create the params array with args and options
        Object[] paramsArray = new Object[2];
        paramsArray[0] = params; // args as an array of strings
        paramsArray[1] = options; // empty options map

        payload.put("params", paramsArray);
        payload.put("id", 0);

        //logger.info("raw request for FreeIPA: " + new ObjectMapper().writeValueAsString(payload));

        StringEntity entity = new StringEntity(new ObjectMapper().writeValueAsString(payload));
        httpPost.setEntity(entity);
        httpPost.setHeader("Content-Type", "application/json");
        httpPost.setHeader("Accept", "application/json");
        httpPost.setHeader("referer", freeipaApiUrl);

        HttpResponse response = client.execute(httpPost, context);
        int statusCode = response.getStatusLine().getStatusCode();
        String responseString = EntityUtils.toString(response.getEntity());

        // Log the raw response for debugging purposes
        //logger.info("Received raw response from FreeIPA: " + responseString);

        if (statusCode != 200) {
            throw new ModelException("Failed to execute FreeIPA API request. Response code: " + statusCode);
        }

        // Attempt to parse the response
        Map<String, Object> result;
        try {
            result = new ObjectMapper().readValue(responseString, Map.class);
            // Log the parsed JSON response
            //logger.info("Parsed JSON response from FreeIPA: " + result);
        } catch (Exception e) {
            throw new ModelException("Failed to parse FreeIPA API response: " + responseString, e);
        }

        // Check for an error key in the response, only throw an exception if the error is not null
        if (result.containsKey("error") && result.get("error") != null) {
            Map<String, Object> error = (Map<String, Object>) result.get("error");
            String errorMessage = error != null ? error.toString() : "null";
            throw new ModelException("FreeIPA API error: " + errorMessage);
        }

        // If there's no error, return the result
        return (Map<String, Object>) result.get("result");
    }


    @Override
    public void passwordUpdateFailed(UserModel userModel, LDAPObject ldapObject, UserCredentialModel userCredentialModel, ModelException e) {
        throw processFailedPasswordUpdateException(ldapObject, e);
    }

    protected ModelException processFailedPasswordUpdateException(LDAPObject ldapObject, ModelException e) {
        logger.infof("Failed to update password for %s through Keycloak. Exception message: %s", ldapObject.getDn(), e.getMessage());
        return e;
    }

    @Override
    public UserModel proxy(LDAPObject ldapObject, UserModel delegate, RealmModel realmModel) {
        return new UserModelDelegate(delegate);
    }

    @Override
    public void beforeLDAPQuery(LDAPQuery ldapQuery) {
        String operationType = inferOperationType(ldapQuery);
        logger.info("Intercepted LDAP Operation: " + operationType);
        logger.info(convertToLDIF(ldapQuery));
    }

    private String inferOperationType(LDAPQuery ldapQuery) {
        // Determine operation type based on the context of usage
        if (ldapQuery.getConditions() != null && !ldapQuery.getConditions().isEmpty()) {
            return "READ";  // Typically, conditions are used for read/search operations
        }

        // You can add more specific logic here based on your needs
        // For example, check specific conditions or search scope

        return "UNKNOWN";  // Fallback if the operation type cannot be determined
    }

    private String convertToLDIF(LDAPQuery ldapQuery) {
        StringBuilder ldifBuilder = new StringBuilder();
        ldifBuilder.append("dn: ").append(ldapQuery.getSearchDn()).append("\n");

        ldifBuilder.append("scope: ").append(getScopeString(ldapQuery.getSearchScope())).append("\n");

        for (Condition condition : ldapQuery.getConditions()) {
            ldifBuilder.append("condition: ").append(condition).append("\n");
        }

        if (!ldapQuery.getReturningLdapAttributes().isEmpty()) {
            ldifBuilder.append("attributes: ").append(String.join(", ", ldapQuery.getReturningLdapAttributes())).append("\n");
        }

        return ldifBuilder.toString();
    }

    private String getScopeString(int searchScope) {
        switch (searchScope) {
            case 0: return "BASE";
            case 1: return "ONELEVEL";
            case 2: return "SUBTREE";
            default: return "UNKNOWN";
        }
    }


    @Override
    public LDAPOperationDecorator beforePasswordUpdate(UserModel userModel, LDAPObject ldapObject, UserCredentialModel userCredentialModel) {
        return null;
    }

    @Override
    public void onImportUserFromLDAP(LDAPObject ldapObject, UserModel userModel, RealmModel realmModel, boolean b) {
    }

    @Override
    public void onRegisterUserToLDAP(LDAPObject ldapObject, UserModel userModel, RealmModel realmModel) {
    }

}
