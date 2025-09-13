//package com.mesutpiskin.keycloak.auth.email;
//
//import org.keycloak.Config;
//import org.keycloak.authentication.Authenticator;
//import org.keycloak.authentication.AuthenticatorFactory;
//import org.keycloak.models.AuthenticationExecutionModel;
//import org.keycloak.models.KeycloakSession;
//import org.keycloak.models.KeycloakSessionFactory;
//import org.keycloak.models.credential.OTPCredentialModel;
//import org.keycloak.provider.ProviderConfigProperty;
//
//import java.util.*;
//
//public class Email2FAAuthenticatorFactory implements AuthenticatorFactory {
//
//    public static final String PROVIDER_ID = "email-2fa-authenticator";
//
//    // Config keys
//    public static final String OTP_LENGTH = "otp-length";
//    public static final String OTP_TTL = "otp-ttl";
//    public static final String MAX_VERIFICATION_ATTEMPT = "max-verification-attempt";
//    public static final String MAX_OTP_ATTEMPT = "max-otp-attempt";
//    public static final String BLOCK_DURATION = "block-duration";
//
//    @Override
//    public String getId() {
//        return PROVIDER_ID;
//    }
//
//    @Override
//    public String getDisplayType() {
//        return "Email OTP 2FA";
//
//    }
//
//    @Override
//    public String getReferenceCategory() {
//        return OTPCredentialModel.TYPE;
//    }
//
//    @Override
//    public boolean isConfigurable() {
//        return true;
//    }
//
//    @Override
//    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
//        return REQUIREMENT_CHOICES;
//    }
//
//    @Override public boolean isUserSetupAllowed() { return false; }
//
//    @Override public String getHelpText() { return "Sends a one-time code to the user's email."; }
//
//    @Override
//    public List<ProviderConfigProperty> getConfigProperties() {
//        List<ProviderConfigProperty> config = new ArrayList<>();
//
//        config.add(createProperty(OTP_LENGTH, "OTP Length", "Length of OTP code", "6"));
//        config.add(createProperty(OTP_TTL, "OTP TTL (seconds)", "OTP expiry in seconds", "180"));
//        config.add(createProperty(MAX_VERIFICATION_ATTEMPT, "Max attempts to verify OTP", "Max wrong entries allowed", "3"));
//        config.add(createProperty(MAX_OTP_ATTEMPT, "Max OTP Attempts", "Max number of resend OTP", "5"));
//        config.add(createProperty(BLOCK_DURATION, "Block Duration (minutes)", "Block user from login", "10"));
//
//        return config;
//    }
//
//    private ProviderConfigProperty createProperty(String name, String label, String help, String defaultValue) {
//        ProviderConfigProperty prop = new ProviderConfigProperty();
//        prop.setName(name);
//        prop.setLabel(label);
//        prop.setHelpText(help);
//        prop.setType(ProviderConfigProperty.STRING_TYPE);
//        prop.setDefaultValue(defaultValue);
//        return prop;
//    }
//
//    @Override
//    public Authenticator create(KeycloakSession session) {
//        return new Email2FAAuthenticator();
//    }
//
//    @Override
//    public void init(Config.Scope scope) {
//
//    }
//
//    @Override
//    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
//
//    }
//
//    // Boilerplate
//    @Override public void close() {}
//}
