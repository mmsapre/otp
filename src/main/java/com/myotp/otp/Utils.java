package com.myotp.otp;

import java.io.File;
import java.io.FileInputStream;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.EncoderException;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.net.URLCodec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Utils {

    private int totpWindowSize;
    private int hotpWindowSize;
    private int hotpCounter;
    private int maxOTPFailure;
    private String issuerName;
    private static SecureRandom secureRandom;
    private static final Logger LOG = LoggerFactory.getLogger(Utils.class);
    protected Utils(File otpFile) throws OTPManagerException {
        loadPropertiesFile(otpFile);
    }
    private void loadPropertiesFile(File otpFile) throws OTPManagerException {
        LOG.debug("Loading properties file...");

        if (!otpFile.exists() || !otpFile.canRead()) {
            LOG.error(Constants.OTP_FILE + " ({}) file does not exist, Please set the correct path",
                    otpFile.getAbsolutePath());
            throw new OTPManagerException(Constants.OTP_FILE + " (" + otpFile.getAbsolutePath()
                    + ") file does not exist, Please set the correct path");
        }

        Properties properties = new Properties();
        FileInputStream inputStream;

        try {
            inputStream = new FileInputStream(otpFile);
            properties.load(inputStream);
            inputStream.close();
        } catch (Exception ex) {
            LOG.error("Failed to load " + Constants.OTP_FILE + " file " + ex.getMessage(), ex);
            throw new OTPManagerException("Failed to load " + Constants.OTP_FILE + " file " + ex.getMessage(), ex);
        }

        readPropertiesFile(properties);
        validatePropertiesFile();
    }
    private void readPropertiesFile(Properties properties) throws OTPManagerException {
        LOG.debug("Reading properties file...");
        try {
            totpWindowSize = Integer.valueOf(properties.getProperty("TOTP.WINDOWSIZE"));
            hotpWindowSize = Integer.valueOf(properties.getProperty("HOTP.WINDOWSIZE"));
            hotpCounter = Integer.valueOf(properties.getProperty("HOTP.COUNTER"));
            maxOTPFailure = Integer.valueOf(properties.getProperty("MAX.OTP.FAILURE"));
            issuerName = properties.getProperty("ISSUER.NAME");
        } catch (Exception ex) {
            LOG.error(Constants.OTP_FILE + " file is incomplete or inaccurate " + ex.getMessage(), ex);
            throw new OTPManagerException(Constants.OTP_FILE + " file is incomplete or inaccurate " + ex.getMessage(),
                    ex);
        }
    }
    private void validatePropertiesFile() throws OTPManagerException {
        if (totpWindowSize <= 0 || hotpWindowSize <= 0 || hotpCounter <= 0 || maxOTPFailure <= 0) {
            LOG.error("Invalid value, Please check file: {}", Constants.OTP_FILE);
            throw new OTPManagerException("Invalid value, Please check file: " + Constants.OTP_FILE);
        }

        // Checking if the window size is between the legal bounds.
        if (totpWindowSize < Constants.MIN_WINDOW || totpWindowSize > Constants.MAX_WINDOW
                || hotpWindowSize < Constants.MIN_WINDOW || hotpWindowSize > Constants.MAX_WINDOW) {
            LOG.error("Invalid TOTP or HOTP window size. ");
            throw new OTPManagerException("Invalid TOTP or HOTP window size. ");
        }
        if (issuerName == null || issuerName.isEmpty()) {
            LOG.error("Issuer name cannot be null or empty, Please check file : " + Constants.OTP_FILE);
            throw new OTPManagerException(
                    "Issuer name cannot be null or empty, Please check file : " + Constants.OTP_FILE);
        }
    }

    protected String generateSharedSecret() throws OTPManagerException {
        LOG.info("Generating shared secret...");

        int value = Constants.SECRET_BITS / 8 + Constants.SCRATCH_CODES * Constants.BYTES_PER_SCRATCH_CODE;
        byte[] sharedSecret = null;
        byte[] encodedSharedSecret = null;
        Base32 codec = new Base32();
        try {
            secureRandom = SecureRandom.getInstance(Constants.RANDOM_NUMBER_ALGORITHM);
            byte[] buffer = new byte[value];
            secureRandom.nextBytes(buffer);
            sharedSecret = Arrays.copyOf(buffer, Constants.SECRET_BITS / 8);
            encodedSharedSecret = codec.encode(sharedSecret);
            reSeed();
        } catch (Exception e) {
            LOG.error("Error while generating shared secret " + e.getMessage(), e);
            throw new OTPManagerException("Error while generating shared secret " + e.getMessage(), e);
        }
        LOG.debug("Generated shared secret successfully");
        return new String(encodedSharedSecret);
    }

    private void reSeed() {
        secureRandom.setSeed(secureRandom.generateSeed(Constants.SEED_SIZE));
    }

    protected long getHotpCode(byte[] sharedSecret, long counter) throws OTPManagerException {
        LOG.debug("HOTP : Generating OTP ...");
        byte[] data = new byte[8];
        long value = counter;

        // Converting the instant of time from the long representation to an
        // array of bytes.
        for (int i = 8; i-- > 0; value >>>= 8) {
            data[i] = (byte) value;
        }
        return generateOTPCode(data, sharedSecret);
    }

    protected long getTotpCode(byte[] sharedSecret, long timeIndex) throws OTPManagerException {
        LOG.debug("TOTP : Generating OTP ...");
        byte[] data = new byte[8];
        long value = timeIndex;

        // Converting the instant of time from the long representation to an
        // array of bytes.
        for (int i = 8; i-- > 0; value >>>= 8) {
            data[i] = (byte) value;
        }

        return generateOTPCode(data, sharedSecret);
    }

    private long generateOTPCode(byte[] data, byte[] sharedSecret) throws OTPManagerException {
        long truncatedHash;
        SecretKeySpec signKey;
        try {
            signKey = new SecretKeySpec(sharedSecret, Constants.HMAC_HASH_FUNCTION);

            // Getting an HmacSHA1 algorithm implementation from the JCE.
            Mac mac = Mac.getInstance(Constants.HMAC_HASH_FUNCTION);

            mac.init(signKey);
            byte[] hash = mac.doFinal(data);
            int offset = hash[hash.length - 1] & 0xF;
            truncatedHash = hash[offset] & 0x7f;

            for (int i = 1; i < 4; i++) {
                truncatedHash <<= 8;
                truncatedHash |= hash[offset + i] & 0xff;
            }
            truncatedHash %= Math.pow(10, Constants.DIGITS);
        } catch (Exception e) {
            LOG.error("Error while generating OTP code " + e.getMessage(), e);
            throw new OTPManagerException("Error while generating OTP code " + e.getMessage(), e);
        }
        LOG.debug("Generated OTP successfully ...");
        return truncatedHash;
    }

    public static String getQRCodeAsURL(String otpAuthURL, int height, int width) throws OTPManagerException {
        if (otpAuthURL == null || otpAuthURL.isEmpty()) {
            LOG.error("otpAuthURL cannot be null or empty");
            throw new OTPManagerException("otpAuthURL cannot be null or empty");
        }
        if (height <= 0 || width <= 0) {
            LOG.error("Height or Width cannot be negative or zero");
            throw new OTPManagerException("Height or Width cannot be negative or zero");
        }

        // Check whether the OPTAuth URL is valid or not
        validateOTPAuthURL(otpAuthURL);

        String qrcodeAsURL;
        String encodedURL;
        URLCodec codec = new URLCodec();

        try {

            encodedURL = codec.encode(otpAuthURL);
        } catch (EncoderException e) {
            LOG.error("Error while encoding otpAuthURL " + e.getMessage(), e);
            throw new OTPManagerException("Error while encoding otpAuthURL " + e.getMessage(), e);
        }

        qrcodeAsURL = Constants.QRCODE_BASE_URL + height + "x" + width + "&chl=" + encodedURL;
        return qrcodeAsURL;
    }

    public static String getSharedSecret(String otpAuthURL) throws OTPManagerException {
        LOG.info("Getting sharedSecret from qrCodeAsURL");
        if (otpAuthURL == null || otpAuthURL.isEmpty()) {
            LOG.error("otpAuthURL cannot be null or empty");
            throw new OTPManagerException("otpAuthURL cannot be null or empty");
        }
        // Check whether the otpAuthURL is valid or not
        validateOTPAuthURL(otpAuthURL);

        int splitAt;
        String sharedSecret;
        String toSearch = "secret=";
        int toSearchLength = toSearch.length();

        try {
            splitAt = otpAuthURL.indexOf(toSearch);
            if (splitAt <= 0) {
                LOG.error("Invalid otpAuth URL, Please check it again");
                throw new OTPManagerException("Invalid otpAuth URL, Please check it again");
            }

            sharedSecret = otpAuthURL.substring(splitAt + toSearchLength,
                    splitAt + toSearchLength + Constants.SHARED_SECRET_LENGTH);

        } catch (Exception e) {
            LOG.error("Invalid otpAuth URL {}", e.getMessage(), e);
            throw new OTPManagerException("Invalid otpAuth URL " + e.getMessage(), e);
        }
        return sharedSecret;
    }

    private static void validateOTPAuthURL(String otpAuthURL) throws OTPManagerException {

        String regex = "otpauth://(hotp|totp)";

        Pattern pattern = Pattern.compile(regex);
        Matcher matches = pattern.matcher(otpAuthURL);

        // OTPAuth URL must be start with otpauth://hotp || otpauth://totp
        if (!matches.lookingAt()) {
            LOG.error("Invalid otpAuth URL, It must be start with either 'otpauth://totp' or 'otpauth://hotp'.");
            throw new OTPManagerException(
                    "Invalid otpAuth URL, It must be start with either 'otpauth://totp' or 'otpauth://hotp'.");
        }
        // following string must be present in OTPAuth url else it will be
        // Invalid
        String[] otpKeyword = { "otpauth", "issuer", "secret", "digits" };
        for (String s : otpKeyword) {
            if (!otpAuthURL.contains(s)) {
                LOG.error("Invalid otpAuth URL, Please check it again");
                throw new OTPManagerException("Invalid otpAuth URL, Please check it again");
            }
        }
    }

    /**
     * Returns the OTP Auth URL
     *
     * @param sharedSecret
     *            sharedSecret of the user
     * @param userInfo
     *            OTP related details of the user
     * @return OTP Auth URL
     */
    protected String generateOTPAuthURL(String sharedSecret, UserInfo userInfo) {
        LOG.info("Generating OTP Auth URL");
        String qrCodeAsURL = null;
        if (userInfo.getType() == Type.TOTP) {
            qrCodeAsURL = "otpauth://totp/" + issuerName + ":" + userInfo.getAccountName() + "?secret=" + sharedSecret
                    + "&issuer=" + issuerName + "&digits=" + Constants.DIGITS + "&period="
                    + Constants.TOTP_TIME_PERIODS;
        } else {
            qrCodeAsURL = "otpauth://hotp/" + issuerName + ":" + userInfo.getAccountName() + "?secret=" + sharedSecret
                    + "&issuer=" + issuerName + "&digits=" + Constants.DIGITS + "&counter=" + hotpCounter;
        }
        LOG.debug("Generated OTP Auth URL");
        return qrCodeAsURL;
    }

    /**
     * @return the totpWindowSize
     */
    protected int getTotpWindowSize() {
        return totpWindowSize;
    }

    /**
     * @return the hotpWindowSize
     */
    protected int getHotpWindowSize() {
        return hotpWindowSize;
    }

    /**
     * @return the hotpCounter
     */
    protected int getHotpCounter() {
        return hotpCounter;
    }

    /**
     * @return the maxOTPFailure
     */
    protected int getMaxOTPFailure() {
        return maxOTPFailure;
    }

}
