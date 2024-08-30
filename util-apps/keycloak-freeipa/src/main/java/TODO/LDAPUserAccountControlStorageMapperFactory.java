package TODO;

import org.keycloak.component.ComponentModel;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapperFactory;

public class LDAPUserAccountControlStorageMapperFactory extends AbstractLDAPStorageMapperFactory {
    @Override
    protected AbstractLDAPStorageMapper createMapper(ComponentModel componentModel, LDAPStorageProvider ldapStorageProvider) {
        return new LDAPUserAccountControlStorageMapper(componentModel, ldapStorageProvider);
    }
    @Override
    public String getId() {
        return "LdapPasswordExpirationMapper";
    }
}
