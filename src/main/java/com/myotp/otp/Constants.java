package com.myotp.otp;

public class Constants {

    public static final int TOTP_TIME_PERIODS = 30;
    public static final int DIGITS = 6;
    public static final String QRCODE_BASE_URL = "http://chart.apis.google.com/chart?cht=qr&chs=";
    public static final int SHARED_SECRET_LENGTH = 16;
    public static final String RANDOM_NUMBER_ALGORITHM = "SHA1PRNG";
    public static final int MIN_WINDOW = 1;
    public static final int MAX_WINDOW = 10;
    public static final int BYTES_PER_SCRATCH_CODE = 4;
    public static final int SEED_SIZE = 128;
    public static final int SECRET_BITS = 80;
    public static final int SCRATCH_CODES = 5;
    public static final String HMAC_HASH_FUNCTION = "HmacSHA1";
    public static final String OTP_FILE = "smart-otp.properties";

}
