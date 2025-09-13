package com.mesutpiskin.keycloak.auth.email;

public class EmailConstants {
	public static final String OTP_CODE_PARAM = "emailCode";
	public static final String OTP_CODE_LENGTH_KEY = "length";
    public static final int OTP_CODE_LENGTH_VALUE = 6;
    public static final String OTP_TTL_KEY = "ttl";
	public static final int OTP_TTL_VALUE = 300;
	public static final String MAX_VERIFICATION_ATTEMPT_KEY = "MAX_VERIFICATION_ATTEMPT";
	public static final int MAX_VERIFICATION_ATTEMPT_VALUE = 4;
    public static final String MAX_RESEND_OTP_KEY = "MAX_RESEND_OTP";
	public static final int MAX_RESEND_OTP_VALUE = 2;
	public static final String RESEND_OTP_TIMEFRAME_KEY = "RESEND_OTP_TIMEFRAME";
	public static final int RESEND_OTP_TIMEFRAME_VALUE = 3;
    public static final String BLOCK_LOGIN_DURATION_KEY = "BLOCK_LOGIN_DURATION";
	public static final int BLOCK_LOGIN_DURATION_VALUE = 5;
	public static final String ENABLE_CONCURRENT_ACCESS_KEY = "ENABLE_CONCURRENT_ACCESS_KEY";
	public static final int ENABLE_CONCURRENT_ACCESS_VALUE = 1;
}
