package TODO;

import org.keycloak.component.ComponentModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapperFactory;
import java.lang.*;
import java.util.ArrayList;
import java.util.List;

public class LDAPUserAccountControlStorageMapperFactory extends AbstractLDAPStorageMapperFactory {

    // Configuration property names
    public static final String FREEIPA_API_URL = "freeipaApiUrl";
    public static final String FREEIPA_USER = "freeipaUser";
    public static final String FREEIPA_PASSWORD = "freeipaPassword";

    @Override
    protected AbstractLDAPStorageMapper createMapper(ComponentModel componentModel, LDAPStorageProvider ldapStorageProvider) {
        return new LDAPUserAccountControlStorageMapper(componentModel, ldapStorageProvider);
    }
    @Override
    public String getId() {
        return "LdapPasswordExpirationMapper";
    }

    @Override
    public String getHelpText() {
        return "LDAP User Account Control Mapper with FreeIPA API integration.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {

        List<ProviderConfigProperty> configProperties = new ArrayList<>();

        ProviderConfigProperty freeipaApiUrl = new ProviderConfigProperty();
        freeipaApiUrl.setName(FREEIPA_API_URL);
        freeipaApiUrl.setLabel("FreeIPA API URL");
        freeipaApiUrl.setHelpText("URL for the FreeIPA API endpoint (e.g., https://freeipa.example.com/ipa/session/json).");
        freeipaApiUrl.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(freeipaApiUrl);

        ProviderConfigProperty freeipaUser = new ProviderConfigProperty();
        freeipaUser.setName(FREEIPA_USER);
        freeipaUser.setLabel("FreeIPA User");
        freeipaUser.setHelpText("Username to authenticate with the FreeIPA API.");
        freeipaUser.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(freeipaUser);

        ProviderConfigProperty freeipaPassword = new ProviderConfigProperty();
        freeipaPassword.setName(FREEIPA_PASSWORD);
        freeipaPassword.setLabel("FreeIPA Password");
        freeipaPassword.setHelpText("Password for the FreeIPA API user.");
        freeipaPassword.setType(ProviderConfigProperty.PASSWORD);
        configProperties.add(freeipaPassword);

        return configProperties;


    }
}
