package com.myotp.otp;

public interface IEncryptor {

    String encrypt(String sharedSecret) throws OTPManagerException;

    String decrypt(String sharedSecret) throws OTPManagerException;
}
