package com.mesutpiskin.keycloak.auth.email;

import org.infinispan.Cache;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.connections.infinispan.InfinispanConnectionProvider;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.common.util.SecretGenerator;

import org.jboss.logging.Logger;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static com.mesutpiskin.keycloak.auth.email.EmailConstants.*;

// This is the class that does the actual logic of the authentication step
public class EmailAuthenticatorForm extends AbstractUsernameFormAuthenticator {

    protected static final Logger logger = Logger.getLogger(EmailAuthenticatorForm.class);
    private static final org.slf4j.Logger log = LoggerFactory.getLogger(EmailAuthenticatorForm.class);

    // Called when Keycloak reaches your step in the login flow (your logic sends OTP, shows form)
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        log.info("__________________________ inside authenticate __________________________");
        if(isUserBlocked(context)){
            showFailure(context, "User is blocked", AuthenticationFlowError.USER_TEMPORARILY_DISABLED);
            return;
        }

        if(isOtpRateLimitExceeded(context)){
            showFailureChallenge(context, "You have exceeded the allowed number of OTP request",
                    AuthenticationFlowError.INVALID_CREDENTIALS);
            return;
        }

        generateAndSendEmailCode(context);
        updateOtpRateLimit(context);

        challenge(context, null);
    }

    // Build a response to re-display the login form with an error message and highlights the input field
    @Override
    protected Response challenge(AuthenticationFlowContext context, String error, String field) {
        log.info("__________________________ inside challenge __________________________");
        LoginFormsProvider form = context.form().setExecution(context.getExecution().getId());
        if (error != null) {
            if (field != null) {
                form.addError(new FormMessage(field, error));
            } else {
                form.setError(error);
            }
        }
        Response response = form.createForm("email-code-form.ftl");
        context.challenge(response);
        return response;
    }

    private void generateAndSendEmailCode(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        AuthenticationSessionModel session = context.getAuthenticationSession();

        if (session.getAuthNote(OTP_CODE_PARAM) != null) {
            // skip sending email code
            return;
        }

        int length = OTP_CODE_LENGTH_VALUE;
        int ttl = OTP_TTL_VALUE;
        if (config != null) {
            // get config values
            length = Integer.parseInt(config.getConfig().get(OTP_CODE_LENGTH_KEY));
            ttl = Integer.parseInt(config.getConfig().get(OTP_TTL_KEY));
        }

        String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
        sendEmailWithCode(context.getSession(), context.getRealm(), context.getUser(), code, ttl);
        session.setAuthNote(OTP_CODE_PARAM, code);
        session.setAuthNote(OTP_TTL_KEY, Long.toString(System.currentTimeMillis() + (ttl * 60 *1000L)));
    }

    // Called when the user submits your form (handles form submission (OTP verification))
    @Override
    public void action(AuthenticationFlowContext context) {
        log.info("__________________________ inside action __________________________");
        AuthenticationSessionModel session = context.getAuthenticationSession();
        UserModel userModel = context.getUser();

        Cache<String, Object> cache = getCache(context);

        // check if user is blocked
        if(isUserBlocked(context)){
            showFailure(context, "User is blocked", AuthenticationFlowError.USER_TEMPORARILY_DISABLED);
            return;
        }

        // check if user is disabled
        if (!enabledUser(context, userModel)) {
            showFailureChallenge(context, "User is Disabled", AuthenticationFlowError.USER_DISABLED);
            // error in context is set in enabledUser/isDisabledByBruteForce
            return;
        }

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("resend")) {
            log.info("_____________________ resend email ____________________");
            if(isOtpRateLimitExceeded(context)){
                showFailureChallenge(context, "You have exceeded the allowed number of OTP request",
                        AuthenticationFlowError.INVALID_CREDENTIALS);
                return;
            }
            resetEmailCode(context);
            generateAndSendEmailCode(context);
            updateOtpRateLimit(context);
            challenge(context, null);
            return;
        }

        if (formData.containsKey("cancel")) {
            resetEmailCode(context);
            context.resetFlow();
            return;
        }

        // auto generated code value
        String code = session.getAuthNote(OTP_CODE_PARAM);
        // otp ttl value
        String ttl = session.getAuthNote(OTP_TTL_KEY);
        // otp code sent by user
        String enteredCode = formData.getFirst(OTP_CODE_PARAM);

        if (enteredCode.equals(code)) {
            // check if otp is expired
            if (Long.parseLong(ttl) < System.currentTimeMillis()) {
                // expired
                context.getEvent().user(userModel).error(Errors.EXPIRED_CODE);
                Response challengeResponse = challenge(context, Messages.EXPIRED_ACTION_TOKEN_SESSION_EXISTS, OTP_CODE_PARAM);
                context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE, challengeResponse);
            } else {
                // valid
                // reset verification count
                cache.put(geeCachePrefix(context)+MAX_VERIFICATION_ATTEMPT_KEY, 0);
                // reset otp rate limit
                cache.put(geeCachePrefix(context)+MAX_RESEND_OTP_KEY, 0);
                resetEmailCode(context);
                context.success();
            }
        } else {
            // get user verification count
            int maxAttemptsConfig = getConfigInt(context, MAX_VERIFICATION_ATTEMPT_KEY, MAX_VERIFICATION_ATTEMPT_VALUE);
            int verificationAttempts = (int) cache.getOrDefault(geeCachePrefix(context)+MAX_VERIFICATION_ATTEMPT_KEY, 0);
            verificationAttempts += 1;
            cache.put(geeCachePrefix(context)+MAX_VERIFICATION_ATTEMPT_KEY, verificationAttempts);
            logger.info("________________ maxAttempts: {} "+maxAttemptsConfig);
            logger.info("________________ verificationAttempts: {} "+verificationAttempts);
            if (verificationAttempts > maxAttemptsConfig) {
                logger.info("------------------ DO BLOCK USER -----------------");
                // block user
                int blockDuration = getConfigInt(context, BLOCK_LOGIN_DURATION_KEY, BLOCK_LOGIN_DURATION_VALUE);
                logger.info("blockDuration: {} "+blockDuration);
                cache.put(geeCachePrefix(context)+ BLOCK_LOGIN_DURATION_KEY, 
                        Long.toString(System.currentTimeMillis() + (blockDuration * 60 *1000L)),
                        blockDuration, TimeUnit.MINUTES);
            }

            // invalid
            AuthenticationExecutionModel execution = context.getExecution();
            if (execution.isRequired()) {
                context.getEvent().user(userModel).error(Errors.INVALID_USER_CREDENTIALS);
                Response challengeResponse = challenge(context, Messages.INVALID_ACCESS_CODE, OTP_CODE_PARAM);
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
            } else if (execution.isConditional() || execution.isAlternative()) {
                context.attempted();
            }
        }
    }

    protected String disabledByBruteForceError() {
        return Messages.INVALID_ACCESS_CODE;
    }

    private void resetEmailCode(AuthenticationFlowContext context) {
        context.getAuthenticationSession().removeAuthNote(OTP_CODE_PARAM);
    }

    // Tells Keycloak whether a user must already be identified before this authenticator runs
    @Override
    public boolean requiresUser() {
        return true;
    }

    // Checks whether this authenticator is active/enabled for the user
    // If you only want to apply it when the user has a certain attribute
    // If it is always required, return true.
    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return user.getEmail() != null;
    }

    // If the authenticator is not configured for a user, you can use this method to trigger a required action
    // EX:  user.addRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // NOOP
    }

    @Override
    public void close() {
        // NOOP
    }

    private void sendEmailWithCode(KeycloakSession session, RealmModel realm, UserModel user, String code, int ttl) {
        if (user.getEmail() == null) {
            logger.warnf("Could not send access code email due to missing email. realm=%s user=%s", realm.getId(), user.getUsername());
            throw new AuthenticationFlowException(AuthenticationFlowError.INVALID_USER);
        }

        Map<String, Object> mailBodyAttributes = new HashMap<>();
        mailBodyAttributes.put("username", user.getUsername());
        mailBodyAttributes.put("code", code);
        mailBodyAttributes.put("ttl", ttl);

        String realmName = realm.getDisplayName() != null ? realm.getDisplayName() : realm.getName();
        List<Object> subjectParams = List.of(realmName);
        try {
            EmailTemplateProvider emailProvider = session.getProvider(EmailTemplateProvider.class);
            emailProvider.setRealm(realm);
            emailProvider.setUser(user);
            // Don't forget to add the welcome-email.ftl (html and text) template to your theme.
            emailProvider.send("emailCodeSubject", subjectParams, "code-email.ftl", mailBodyAttributes);
        } catch (EmailException eex) {
            logger.errorf(eex, "Failed to send access code email. realm=%s user=%s", realm.getId(), user.getUsername());
        }
    }

    private int getConfigInt(AuthenticationFlowContext context, String key, int defaultVal) {
        try {
            String val = context.getAuthenticatorConfig().getConfig().get(key);
            return val == null ? defaultVal : Integer.parseInt(val);
        } catch (Exception e) {
            return defaultVal;
        }
    }

    private Cache<String, Object> getCache(AuthenticationFlowContext context) {
        InfinispanConnectionProvider provider = context.getSession().getProvider(InfinispanConnectionProvider.class);
        return provider.getCache(InfinispanConnectionProvider.SESSION_CACHE_NAME);
    }

    private boolean isUserBlocked(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        logger.info("________________ isUserBlocked() __________________");
        Cache<String, Object> cache = getCache(context);
        String blockCache = (String) cache.get(geeCachePrefix(context)+BLOCK_LOGIN_DURATION_KEY);
        logger.info("________________ VALUE: "+blockCache);
        if(blockCache != null) {
            logger.info("BLOCKED UNTIL: {}" + blockCache);
            return System.currentTimeMillis() < Long.parseLong(blockCache);
        }
        return false;
    }

    private boolean isOtpRateLimitExceeded(AuthenticationFlowContext context) {
        Cache<String, Object> cache = getCache(context);
        
        // get timeframe window
        int otpTimeframeWindowConfig = getConfigInt(context, RESEND_OTP_TIMEFRAME_KEY, 5);
        
        // get max number of allowed otp requests
        int maxAllowedOtpRequestConfig = getConfigInt(context, MAX_RESEND_OTP_KEY, 3);

        // get number of request sent by use
        int otpRequestsCount = (int) cache.getOrDefault(geeCachePrefix(context)+MAX_RESEND_OTP_KEY, 0);

        logger.info("otpTimeframeWindowConfig: "+ otpTimeframeWindowConfig);
        logger.info("maxAllowedOtpRequestConfig: "+ maxAllowedOtpRequestConfig);
        logger.info("otpRequestsCount: "+ otpRequestsCount);
        if(otpRequestsCount+1 > maxAllowedOtpRequestConfig) {
            logger.info("---------------- PREVENT RESEND OTP ----------------");
            // invalid
            return true;
        }
        return false;
    }

    private void updateOtpRateLimit(AuthenticationFlowContext context) {
        Cache<String, Object> cache = getCache(context);

        // get timeframe window
        int otpTimeframeWindowConfig = getConfigInt(context, RESEND_OTP_TIMEFRAME_KEY, 5);

        // get number of request sent by use
        int otpRequestsCount = (int) cache.getOrDefault(geeCachePrefix(context)+MAX_RESEND_OTP_KEY, 0);
        otpRequestsCount += 1;
        cache.put(geeCachePrefix(context)+MAX_RESEND_OTP_KEY, otpRequestsCount, otpTimeframeWindowConfig, TimeUnit.MINUTES);
    }
    
    private String geeCachePrefix(AuthenticationFlowContext context) {
        return context.getUser().getId()+":";
    }

    private void showFailureChallenge(AuthenticationFlowContext context, String message, AuthenticationFlowError authenticationFlowError) {
        AuthenticationExecutionModel execution = context.getExecution();
        if (execution.isRequired()) {
            context.getEvent().user(context.getUser()).error(message);
            Response challengeResponse = challenge(context, message);
            context.failureChallenge(authenticationFlowError, challengeResponse);
        } else if (execution.isConditional() || execution.isAlternative()) {
            context.attempted();
        }
    }

    private void showFailure(AuthenticationFlowContext context, String message, AuthenticationFlowError authenticationFlowError) {
        AuthenticationExecutionModel execution = context.getExecution();
        if (execution.isRequired()) {
            context.getEvent().user(context.getUser()).error(message);
            context.failure(authenticationFlowError);
        } else if (execution.isConditional() || execution.isAlternative()) {
            context.attempted();
        }
    }

}
