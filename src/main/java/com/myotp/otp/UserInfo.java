package com.myotp.otp;

public class UserInfo {

    private String userId;
    private String accountName;
    private Type type;
    private String sharedSecret;
    private boolean status;
    private int failureCounter;
    private long hotpCounter;

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getAccountName() {
        return accountName;
    }

    public void setAccountName(String accountName) {
        this.accountName = accountName;
    }

    public Type getType() {
        return type;
    }

    public void setType(Type type) {
        this.type = type;
    }

    public String getSharedSecret() {
        return sharedSecret;
    }

    public void setSharedSecret(String sharedSecret) {
        this.sharedSecret = sharedSecret;
    }

    public boolean isStatus() {
        return status;
    }

    public void setStatus(boolean status) {
        this.status = status;
    }

    public int getFailureCounter() {
        return failureCounter;
    }

    public void setFailureCounter(int failureCounter) {
        this.failureCounter = failureCounter;
    }

    public long getHotpCounter() {
        return hotpCounter;
    }

    public void setHotpCounter(long hotpCounter) {
        this.hotpCounter = hotpCounter;
    }
}
