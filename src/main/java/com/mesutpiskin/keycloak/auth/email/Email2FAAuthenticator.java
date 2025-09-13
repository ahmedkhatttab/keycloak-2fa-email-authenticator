//package com.mesutpiskin.keycloak.auth.email;
//
//import jakarta.ws.rs.core.Response;
//import org.keycloak.authentication.*;
//import org.keycloak.email.EmailException;
//import org.keycloak.email.EmailTemplateProvider;
//import org.keycloak.models.*;
//import org.keycloak.sessions.AuthenticationSessionModel;
//
//import javax.ws.rs.core.MultivaluedMap;
//import java.util.*;
//
//import static com.mesutpiskin.keycloak.auth.email.Email2FAAuthenticatorFactory.MAX_VERIFICATION_ATTEMPT;
//
//public class Email2FAAuthenticator implements Authenticator {
//
//    private static final String CODE_NOTE = "email_2fa_code";
//    private static final String CODE_EXPIRY_NOTE = "email_2fa_code_expiry";
//    private static final String ATTEMPTS_NOTE = "email_2fa_attempts";
//    private static final String VERIFICATION_NOTE = "email_2fa_verification";
//    private static final String BLOCK_UNTIL_NOTE = "email_2fa_block_until";
//
//    @Override
//    public void authenticate(AuthenticationFlowContext context) {
//        AuthenticationSessionModel session = context.getAuthenticationSession();
//        UserModel user = context.getUser();
//
//        if (isBlocked(session)) {
//            context.failureChallenge(AuthenticationFlowError.USER_TEMPORARILY_DISABLED,
//                    context.form().setError("Too many failed attempts. Try again later.")
//                            .createForm("email-code-form.ftl"));
//            return;
//        }
//
//        // Handle OTP resend logic
//        int max_opt_request = getIntNote(session, ATTEMPTS_NOTE, 0);
//        int maxRequests = getConfigInt(context, Email2FAAuthenticatorFactory.MAX_OTP_ATTEMPT, 3);
//
//        if (max_opt_request >= maxRequests) {
//            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
//                    context.form().setError("OTP resend limit reached").createForm("email-code-form.ftl"));
//            return;
//        }
//
//        // Generate and send OTP
//        String code = generateOtp(getConfigInt(context, Email2FAAuthenticatorFactory.OTP_LENGTH, 6));
//        long ttlMs = getConfigInt(context, Email2FAAuthenticatorFactory.OTP_TTL, 180) * 1000L;
//
//        session.setAuthNote(CODE_NOTE, code);
//        session.setAuthNote(CODE_EXPIRY_NOTE, String.valueOf(System.currentTimeMillis() + ttlMs));
//        session.setAuthNote(MAX_VERIFICATION_ATTEMPT, String.valueOf(max_opt_request + 1));
//
//        try {
//            Map<String, Object> attributes = new HashMap<>();
//            attributes.put("code", code);
//            attributes.put("ttl", Email2FAAuthenticatorFactory.OTP_TTL);
//
//            context.getSession().getProvider(EmailTemplateProvider.class)
//                    .setRealm(context.getRealm())
//                    .setUser(user)
//                    .send("email-otp-subject", "email-otp-template", attributes);
//        } catch (EmailException e) {
//            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
//            return;
//        }
//
//        Response challenge = context.form().createForm("email-code-form.ftl");
//        context.challenge(challenge);
//    }
//
//    @Override
//    public void action(AuthenticationFlowContext context) {
//        AuthenticationSessionModel session = context.getAuthenticationSession();
//        String inputCode = context.getHttpRequest().getDecodedFormParameters().getFirst("code");
//
//        String expectedCode = session.getAuthNote(CODE_NOTE);
//        long expiry = Long.parseLong(session.getAuthNote(CODE_EXPIRY_NOTE));
//        int attempts = getIntNote(session, VERIFICATION_NOTE, 0);
//        int maxAttempts = getConfigInt(context, Email2FAAuthenticatorFactory.MAX_OTP_ATTEMPT, 5);
//
//        if (System.currentTimeMillis() > expiry) {
//            context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
//                    context.form().setError("OTP expired").createForm("email-code-form.ftl"));
//            return;
//        }
//
//        if (expectedCode != null && expectedCode.equals(inputCode)) {
//            context.success();
//        } else {
//            attempts++;
//            session.setAuthNote(ATTEMPTS_NOTE, String.valueOf(attempts));
//
//            if (attempts >= maxAttempts) {
//                long blockDuration = getConfigInt(context, Email2FAAuthenticatorFactory.BLOCK_DURATION, 10);
//                session.setAuthNote(BLOCK_UNTIL_NOTE,
//                        String.valueOf(System.currentTimeMillis() + blockDuration * 60 * 1000));
//                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
//                        context.form().setError("Too many attempts. You're temporarily blocked.")
//                                .createForm("email-code-form.ftl"));
//            } else {
//                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
//                        context.form().setError("Invalid code").createForm("email-code-form.ftl"));
//            }
//        }
//    }
//
//    private boolean isBlocked(AuthenticationSessionModel session) {
//        String blockUntil = session.getAuthNote(BLOCK_UNTIL_NOTE);
//        if (blockUntil == null) return false;
//        return System.currentTimeMillis() < Long.parseLong(blockUntil);
//    }
//
//    private String generateOtp(int length) {
//        Random r = new Random();
//        StringBuilder sb = new StringBuilder();
//        for (int i = 0; i < length; i++) {
//            sb.append(r.nextInt(10));
//        }
//        return sb.toString();
//    }
//
//    private int getIntNote(AuthenticationSessionModel session, String key, int defaultVal) {
//        try {
//            String val = session.getAuthNote(key);
//            return val == null ? defaultVal : Integer.parseInt(val);
//        } catch (Exception e) {
//            return defaultVal;
//        }
//    }
//
//    private int getConfigInt(AuthenticationFlowContext context, String key, int defaultVal) {
//        try {
//            String val = context.getAuthenticatorConfig().getConfig().get(key);
//            return val == null ? defaultVal : Integer.parseInt(val);
//        } catch (Exception e) {
//            return defaultVal;
//        }
//    }
//
//    @Override public boolean requiresUser() { return true; }
//    @Override public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) { return true; }
//    @Override public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}
//    @Override public void close() {}
//}
