package com.mesutpiskin.keycloak.auth.email;

import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;

import static com.mesutpiskin.keycloak.auth.email.EmailConstants.*;

// register your provider with keycloak and create an instance of Authenticator
public class EmailAuthenticatorFormFactory implements AuthenticatorFactory {
    // the name which appears in the provider list
    public static final String PROVIDER_ID = "email-authenticator";
	public static final EmailAuthenticatorForm SINGLETON = new EmailAuthenticatorForm();

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    /**
     * the name which appears in authentication flow -> add execution -> search
     * @return
     */
    @Override
    public String getDisplayType() {
        return "Email OTP";
    }

    @Override
    public String getReferenceCategory() {
    	return OTPCredentialModel.TYPE;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    /**
     * appear as hint
     * @return
     */
    @Override
    public String getHelpText() {
        return "Email otp authenticator.";
    }

    /**
     * We just define configs name & description
     * @return
     */
    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
//        return List.of(
//                new ProviderConfigProperty(EmailConstants.CODE_LENGTH, "Code length",
//                        "The number of digits of the generated code.",
//                        ProviderConfigProperty.STRING_TYPE, String.valueOf(EmailConstants.DEFAULT_LENGTH)),
//                new ProviderConfigProperty(EmailConstants.CODE_TTL, "Time-to-live",
//                        "The time to live in seconds for the code to be valid.", ProviderConfigProperty.STRING_TYPE,
//                        String.valueOf(EmailConstants.DEFAULT_TTL)));

        return List.of(
                createProperty(OTP_CODE_LENGTH_KEY, "Code length",
                        "The number of digits of the generated code", String.valueOf(OTP_CODE_LENGTH_VALUE)),
                createProperty(OTP_TTL_KEY, "Time-to-live",
                        "The time to live in minutes for the code to be valid", String.valueOf(OTP_TTL_VALUE)),
                createProperty(MAX_VERIFICATION_ATTEMPT_KEY, "Verification Attempts",
                        "Maximum number of tries to verify OTP", String.valueOf(MAX_VERIFICATION_ATTEMPT_VALUE)),
                createProperty(MAX_RESEND_OTP_KEY, "Resend New OTP",
                        "Maximum number of tries to resend OTP", String.valueOf(MAX_RESEND_OTP_VALUE)),
                createProperty(BLOCK_LOGIN_DURATION_KEY, "BLOCK LOGIN DURATION",
                        "Block user from login fo a specific (x) in minutes", String.valueOf(BLOCK_LOGIN_DURATION_VALUE)),
                createProperty(RESEND_OTP_TIMEFRAME_KEY, "Timeframe window in minutes to resend OTP",
                        "Set how many OTP can send within a certain timeframe", String.valueOf(RESEND_OTP_TIMEFRAME_VALUE))
        );
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void close() {
        // NOOP
    }

    @Override
    public void init(Config.Scope config) {
        // NOOP
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // NOOP
    }

    private ProviderConfigProperty createProperty(String name, String label, String help, String defaultValue) {
        ProviderConfigProperty prop = new ProviderConfigProperty();
        prop.setName(name);
        prop.setLabel(label);
        prop.setHelpText(help);
        prop.setType(ProviderConfigProperty.STRING_TYPE);
        prop.setDefaultValue(defaultValue);
        return prop;
    }
}
