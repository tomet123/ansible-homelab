package TODO;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.ModelException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.UserModelDelegate;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.idm.model.LDAPObject;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQuery;
import org.keycloak.storage.ldap.idm.store.ldap.LDAPOperationManager;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.LDAPOperationDecorator;
import org.keycloak.storage.ldap.mappers.PasswordUpdateCallback;

import javax.naming.directory.*;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;


public class LDAPUserAccountControlStorageMapper extends AbstractLDAPStorageMapper implements PasswordUpdateCallback {

    private final LDAPOperationManager operationManager;

    /* This decorator could be instantiated and implement the function
     beforeLDAPOperation(LdapContext ldapContext, LDAPOperationManager.LdapOperation ldapOperation)
     See base class at
     federation/ldap/src/main/java/org/keycloak/storage/ldap/mappers/LDAPOperationDecorator.java
     or an example implementation at
     org/keycloak/storage/ldap/mappers/msad/LDAPServerPolicyHintsDecorator.java:39
     This could possibly enforce some of the LDAP pwpolicy entries that Keycloak itself cannot
    */
    private final LDAPOperationDecorator passwordUpdateDecorator = null;
    private final String USER_EXTRA_ATTRIBUTE = "krbLastPwdChange";
    private final String USER_FAILED_LOGIN_COUNT = "krbLoginFailedCount";
    private final String USER_PASSWORD_EXPIRATION = "krbPasswordExpiration";
    private final String KRB_PWD_POLICY = "krbPwdPolicy";
    private final String GLOBAL_POLICY = "cn=global_policy";
    private final String POLICY_MAX_PWD_LIFE = "krbMaxPwdLife";

    /* Attributes of note:
     * krbPasswordExpiration - time of now +
     *      cn=global_policy,cn=KERB.DOMAIN,cn=kerberos,dc=LDAP,dc=DOMAIN
     *      krbmaxpwdlife: 7776000 (seconds)
     * krbLastPwdChange - time of now
     * krbLoginFailedCount - reset to 0
     */
    private static final Logger logger = Logger.getLogger(LDAPUserAccountControlStorageMapper.class);

    public LDAPUserAccountControlStorageMapper(ComponentModel mapperModel, LDAPStorageProvider ldapProvider) {
        super(mapperModel, ldapProvider);
        this.operationManager = new LDAPOperationManager(session, ldapProvider.getLdapIdentityStore().getConfig());
        ldapProvider.setUpdater(this);
    }

    @Override
    public void passwordUpdated(UserModel userModel, LDAPObject ldapObject, UserCredentialModel userCredentialModel) {

        try {

            // Create the dn to read the global password policy
            LdapName ldapName = ldapObject.getDn().getLdapName();

            List<Rdn> rdns = ldapName.getRdns().reversed();
            /* This is required because the list comes out w/ L[0] == last entry, L[1] second to last
             So `uid=bob,dc=earth,dc=com` ends up:
             rdns[0] = dc=com
             rdns[1] = dc=earth
             rdns[2] = uid=bob
            See https://docs.oracle.com/javase/8/docs/api/javax/naming/ldap/LdapName.html
            "The right most RDN is at index 0, and the left most RDN is at index n-1."
            There ought to be an official function to extract the dc= but I never found it
            */

            String dcDn = rdns.stream().filter(rdn -> rdn.getType().equalsIgnoreCase("DC")).map(Rdn::toString).collect(Collectors.joining(","));
            String Realm = dcDn.replace("dc=", "").toUpperCase().replace(",", ".");
            // I.e, convert `dc=earth,dc=com` to `EARTH.COM`

            String policyDn = GLOBAL_POLICY + ",cn=" + Realm + ",cn=kerberos," + dcDn;
            // should be of the form: `cn=global_policy,cn=KERB.DOMAIN,cn=kerberos,dc=LDAP,dc=DOMAIN"`

            /*
            Example `global_policy` DN, and the attributes in it
                cn=global_policy,cn=KERB.DOMAIN,cn=kerberos,dc=LDAP,dc=DOMAIN
            Plausible attributes:
                krbMinPwdLife: 0
                krbPwdMinDiffChars: 0
                krbPwdMinLength: 8
                krbPwdHistoryLength: 0
                krbMaxPwdLife: 7776000
                krbPwdMaxFailure: 6
                krbPwdFailureCountInterval: 60
                krbPwdLockoutDuration: 600
                passwordGraceLimit: -1
            */

            /*
            Retrieve the relevant attribute, and do some math
             */
            Set<String> myAttr = new HashSet<>();
            myAttr.add(POLICY_MAX_PWD_LIFE); // measured in seconds
            LdapName ll = new LdapName(policyDn);
            List<SearchResult> search = operationManager.search(ll, "(objectClass=" + KRB_PWD_POLICY + ")", myAttr, SearchControls.OBJECT_SCOPE);
            Attributes ids = search.get(0).getAttributes();
            long krbMaxPwdLife = Long.parseLong(ids.get(POLICY_MAX_PWD_LIFE).get().toString());

            // Get current time, add the seconds in POLICY_MAX_PWD_LIFE
            ZonedDateTime nowUTC = ZonedDateTime.now(ZoneId.of("UTC"));
            ZonedDateTime newTimeUTC = nowUTC.plusSeconds(krbMaxPwdLife);

            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'");
            String formattedDateTime = newTimeUTC.format(formatter);

            // Note: size of this array is fixed at 1!
            ModificationItem[] mods = new ModificationItem[1];
            BasicAttribute attr = new BasicAttribute(USER_PASSWORD_EXPIRATION, formattedDateTime);
            mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, attr);

            // Here's the magic: set USER_PASSWORD_EXPIRATION otherwise the password is immediately expired!
            operationManager.modifyAttributes(ldapObject.getDn().getLdapName(), mods, passwordUpdateDecorator);

        } catch (ModelException me) {
            throw processFailedPasswordExpiration(ldapObject, me);
        } catch (Exception e) {
            throw new ModelException("Unknown error updating attributes.", e);
        }
    }

    @Override
    public void passwordUpdateFailed(UserModel userModel, LDAPObject ldapObject, UserCredentialModel userCredentialModel, ModelException e) {
        throw processFailedPasswordUpdateException(ldapObject, e);
    }

    protected ModelException processFailedPasswordUpdateException(LDAPObject ldapObject, ModelException e) {
        if (e.getCause() == null || e.getCause().getMessage() == null) {
            return e;
        }
        String exceptionMessage = e.getCause().getMessage();
        logger.infof("Failed to update password for %s through Keycloak. Exception message: %s", ldapObject.getDn(), exceptionMessage);
        return e;
    }

    protected ModelException processFailedPasswordExpiration(LDAPObject ldapObject, ModelException e) {
        if (e.getCause() == null || e.getCause().getMessage() == null) {
            return e;
        }
        String exceptionMessage = e.getCause().getMessage();
        logger.infof("Failed to update password expiration attribute %s for %s through Keycloak. Exception message: %s", USER_PASSWORD_EXPIRATION, ldapObject.getDn(), exceptionMessage);
        return e;
    }

    @Override
    public UserModel proxy(LDAPObject ldapObject, UserModel delegate, RealmModel realmModel) {
        return new UserModelDelegate(delegate);
    }

    @Override
    public void beforeLDAPQuery(LDAPQuery ldapQuery) {
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
