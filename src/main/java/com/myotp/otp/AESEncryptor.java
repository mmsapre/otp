package com.myotp.otp;

import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AESEncryptor implements IEncryptor{

    private StandardPBEStringEncryptor encrytor;

    private static final Logger LOG = LoggerFactory.getLogger(AESEncryptor.class);

    public AESEncryptor() {
        encrytor = new StandardPBEStringEncryptor();
        encrytor.setAlgorithm("PBEWithMD5AndDES");

        encrytor.setPassword("ZgPiPSCdq88K8Mfay7T7IA");
    }

    public String encrypt(String sharedSecret) throws OTPManagerException {
        LOG.info("Encrypting shared Secret...");
        if (sharedSecret == null || sharedSecret.isEmpty()) {
            LOG.error("SharedSecret cannot be null or empty");
            throw new OTPManagerException("SharedSecret cannot be null or empty");
        }
        String encryptedKey = null;
        try {
            encryptedKey = encrytor.encrypt(sharedSecret);
        } catch (Exception e) {
            LOG.error("Error while encrypting sharedSecret {}", e.getMessage(), e);
            throw new OTPManagerException("Error while encrypting sharedSecret " + e.getMessage(), e);
        }
        LOG.debug("Encrypted Shared Secret successfully");
        return encryptedKey;
    }

    public String decrypt(String sharedSecret) throws OTPManagerException {
        LOG.info("Decrypting shared Secret...");
        String decryptedKey = null;
        if (sharedSecret == null || sharedSecret.isEmpty()) {
            LOG.error("SharedSecret cannot be null or empty");
            throw new OTPManagerException("SharedSecret cannot be null or empty");
        }
        try {
            decryptedKey = encrytor.decrypt(sharedSecret);
        } catch (Exception e) {
            // for Invalid sharedSecret, e.getMessage will be null
            LOG.error("Error while decrypting sharedSecret {}", e.getMessage(), e);
            throw new OTPManagerException("Error while decrypting sharedSecret " + e.getMessage(), e);
        }
        LOG.debug("Decrypted Shared Secret successfully");
        return decryptedKey;
    }

}
