package com.myotp.otp;

public interface IUserInfoDAO {

    public void write(UserInfo userInfo) throws OTPManagerException;

    public UserInfo read(String userId) throws OTPManagerException;
}
