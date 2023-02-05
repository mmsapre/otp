package com.myotp.otp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import org.apache.commons.codec.binary.Base32;
public class OTPManager {

    private IUserInfoDAO userInfoDAO;
    private IEncryptor encryptor;
    private Utils utils;

    private static final Logger LOG = LoggerFactory.getLogger(OTPManager.class);

    public void init(File PropertiesFile, IUserInfoDAO userInfoDAO,
                     IEncryptor encryptor) throws OTPManagerException {
        LOG.info("Initializing properties file and references...");
        if (PropertiesFile == null || userInfoDAO == null) {
            LOG.error("OTP file path or IUserInfoDao are not set. Please initialize it");
            throw new OTPManagerException(
                    "OTP file path or IUserInfoDao are not set. Please initialize it");
        }
        this.userInfoDAO = userInfoDAO;
        utils = new Utils(PropertiesFile);
        if (encryptor == null) {
            LOG.info("No Reference found for IEncryptor, Setting  AESEncryptor by Default. ");
            this.encryptor = new AESEncryptor();
        } else {
            this.encryptor = encryptor;
        }
    }


    public String register(UserInfo userInfo) throws OTPManagerException {
        LOG.info("Registering user...");
        String sharedSecret = null;
        String otpAuthURL = null;

        if (userInfo == null) {
            LOG.error("UserInfo cannot be null");
            throw new OTPManagerException("UserInfo cannot be null");
        }
        if (userInfo.getAccountName() == null
                || userInfo.getAccountName().isEmpty()) {
            LOG.error("Account name cannot be null or empty");
            throw new OTPManagerException(
                    "Account name cannot be null or empty");
        }

        if (userInfo.getType() == null) {
            LOG.error("OTP type cannot be null or empty");
            throw new OTPManagerException("OTP type cannot be null or empty");
        }

        try {
            sharedSecret = utils.generateSharedSecret();
            otpAuthURL = utils.generateOTPAuthURL(sharedSecret, userInfo);
            userInfo.setSharedSecret(encryptor.encrypt(sharedSecret));
            userInfo.setStatus(true);
            userInfo.setFailureCounter(0);
             if (userInfo.getType() == Type.HOTP)
                userInfo.setHotpCounter(utils.getHotpCounter());

             userInfoDAO.write(userInfo);
        } catch (Exception e) {
            LOG.error("Erroring while doing OTP registration {}",
                    e.getMessage(), e);
            throw new OTPManagerException(
                    "Erroring while doing OTP registration {}" + e.getMessage(),
                    e);
        }
        return otpAuthURL;
    }

    public boolean verifyOTP(String otpCode, String userId)
            throws OTPManagerException {
        LOG.info("Verifying OTP for user : " + userId);
        if (otpCode == null || otpCode.isEmpty() || userId == null
                || userId.isEmpty()) {
            LOG.error("OTP Code or UserId cannot be null or empty");
            throw new OTPManagerException(
                    "OTP Code or UserId cannot be null or empty");
        }

        if (otpCode.length() != Constants.DIGITS) {
            LOG.error("The given otp " + otpCode
                    + " has wrong length. Expected " + Constants.DIGITS
                    + " digits");
            throw new OTPManagerException("The given otp " + otpCode
                    + " has wrong length. Expected " + Constants.DIGITS
                    + " digits");
        }

        long code;
        try {
            code = Long.valueOf(otpCode);
        } catch (NumberFormatException nfe) {
            LOG.error("Invalid OTP code: {}", otpCode, nfe);
            throw new OTPManagerException("Invalid OTP code: " + otpCode, nfe);
        }

        if (code <= 0) {
            LOG.error("OTP code cannot be zero or negative");
            throw new OTPManagerException("OTP code cannot be zero or negative");
        }

        // Read the user details
        UserInfo userInfo = null;
        try {
            userInfo = userInfoDAO.read(userId);
            // for Invalid userId
            if (userInfo == null) {
                LOG.error(
                        "Invalid userId, {} is not registered for OTP Authentication",
                        userId);
                throw new OTPManagerException("Invalid userId, " + userId
                        + " is not registered for OTP Authentication");
            }
        } catch (Exception e) {
            LOG.error("Error while reading userDetails from the database {}",
                    e.getMessage(), e);
            throw new OTPManagerException(
                    "Error while reading userDetails from the database "
                            + e.getMessage(), e);
        }


        if (!userInfo.isStatus()) {
            LOG.error(
                    "UserId '{}' is blocked, Please contact System Administrator",
                    userId);
            throw new OTPManagerException("UserId '" + userId
                    + "' is blocked, Please contact System Administrator");
        }

        String sharedSecret = null;
        try {
            sharedSecret = encryptor.decrypt(userInfo.getSharedSecret());
        } catch (Exception e) {
            LOG.error("Error while decrypting the sharedSecret {} ",
                    e.getMessage(), e);
            throw new OTPManagerException(
                    "Error while decrypting the sharedSecret " + e.getMessage(),
                    e);
        }

        boolean otpResult = false;
        long generateOTPCode;
        int variance;
        long hotpCounter = 0;

        try {
            // Decoding the secret key to get its raw byte representation.
            byte[] secretInBytes = new Base32().decode(sharedSecret);

            if (userInfo.getType() == Type.HOTP) {
                variance = utils.getHotpWindowSize();
                hotpCounter = userInfo.getHotpCounter();
                for (int i = 0; i <= variance; i++) {
                    generateOTPCode = utils.getHotpCode(secretInBytes,
                            hotpCounter + i);

                    // if generared == OTP code to be verified.
                    if (generateOTPCode == code) {
                        otpResult = true;
                        userInfo.setHotpCounter(hotpCounter + i);
                        break;
                    }
                }
            } else {
                variance = utils.getTotpWindowSize();

                // -ve to check both side of time interval
                for (int i = -variance; i < variance; i++) {
                    // Calculating the verification code for the current time
                    // interval.
                    generateOTPCode = utils.getTotpCode(secretInBytes,
                            getTimeIndex() + i);
                    // if generared == OTP code to be verified.
                    if (generateOTPCode == code) {
                        otpResult = true;
                        break;
                    }
                }
            }
            if (otpResult == false) {
                userInfo = checkThrottlingCounter(userInfo);
            } else {
                userInfo.setFailureCounter(0);
            }
            userInfoDAO.write(userInfo);
        } catch (Exception e) {
            LOG.error("Error while verifying OTP {}", e.getMessage(), e);
            throw new OTPManagerException("Error while verifying OTP "
                    + e.getMessage(), e);
        }
        return otpResult;
    }


    private long getTimeIndex() {
        return System.currentTimeMillis() / 1000 / Constants.TOTP_TIME_PERIODS;
    }


    private UserInfo checkThrottlingCounter(UserInfo userInfo)
            throws OTPManagerException {
        int failureCounter = userInfo.getFailureCounter();

        if (failureCounter < 0) {
            LOG.error("Failure counter cannot be negative");
            throw new OTPManagerException("Failure counter cannot be negative");
        }

        int totalFailureCounter = failureCounter + 1;

        // If failure Counter reached MAX_OTP_FAILURE, block the user
        if (totalFailureCounter >= utils.getMaxOTPFailure()) {
            userInfo.setStatus(false);
        }
        userInfo.setFailureCounter(totalFailureCounter);
        return userInfo;
    }
}
