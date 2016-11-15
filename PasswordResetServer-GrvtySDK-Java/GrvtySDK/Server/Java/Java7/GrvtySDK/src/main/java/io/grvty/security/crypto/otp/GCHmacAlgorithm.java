/*
 * Created by Jaime Chon on 1/30/16.
 */
package io.grvty.security.crypto.otp;

/**
 * Enum of the valid HMAC algorithms to be used
 * in the OTP generation
 */
public enum GCHmacAlgorithm {
    HmacSHA1("HmacSHA1", 20),
    HmacSHA256("HmacSHA256", 32),
    HmacSHA512("HmacSHA512", 64),
    DEFAULT("HmacSHA256", 32);

    private final String algorithm;
    private final int digestLength;

    GCHmacAlgorithm(String algorithm, int digestLength) {
        this.algorithm = algorithm;
        this.digestLength = digestLength;
    }

    /**
     * Get the Java Mac algorithm
     * @return Hmac algorithm
     */
    public String getAlgorithm() {
        return this.algorithm;
    }

    /**
     * Get the length of the digest of the Hmac algorithm
     * @return Hmac digest length
     */
    public int getDigestLength() {
        return this.digestLength;
    }

    @Override
    public String toString() {
        return "GCHmacAlgorithm{" +
                "algorithm='" + algorithm + '\'' +
                ", digestLength=" + digestLength +
                '}';
    }
}