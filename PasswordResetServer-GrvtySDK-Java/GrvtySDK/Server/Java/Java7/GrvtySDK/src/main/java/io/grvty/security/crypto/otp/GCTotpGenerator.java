/*
 * Created by Jaime Chon on 9/9/15.
 */
package io.grvty.security.crypto.otp;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Arrays;

/**
 * Generate TOTP tokens. This token generator complies with RFC 6238.
 */
public class GCTotpGenerator {
    private static Log log = LogFactory.getLog(GCTotpGenerator.class);
    private final GCOtpGenerator generator;
    private final GCTotpCounter totpCounter;

    public GCTotpGenerator(GCOtpGenerator generator, GCTotpCounter totpCounter) {
        this.generator = generator;
        this.totpCounter = totpCounter;
    }

    /**
     * Generate OTP token given a key and data (time period + unique user id)
     * @throws GeneralSecurityException if an error occurred with the cryptographic function
     * @param key (device secret ^ app secret)
     * @param data (time period + unique user id)
     * @return otp token
     */
    public String generateOtpToken(Key key, byte[] data) throws GeneralSecurityException {
        if (key == null) {
            throw new IllegalArgumentException("Key key can't be null.");
        }
        if (data == null) {
            throw new IllegalArgumentException("data[] data can't be null");
        }
        if (data.length < 8) {
            throw new IllegalArgumentException(String.format("byte[] data is %s bytes. Must be at least 8 bytes.", data.length));
        }
        String token = generator.generateOtp(key, data);
        log.trace(String.format("Token:%s generated for key:%s\tdata:%s", token, key, Arrays.toString(data)));
        return token;
    }

    public String generateOtpToken(Key key) {
        if (key == null) {
            throw new IllegalArgumentException("Key key can't be null.");
        }
        try {
            long period = totpCounter.totpCount();
            String token = generator.generateOtp(key, periodToBytes(period));
            log.trace(String.format("Token:%s generated for key:%s\tperiod:%s", token, key, period));
            return token;
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            throw new RuntimeException(e.toString());
        }
    }

    /**
     * Get the length of generated OTP tokens
     * @return OTP token length
     */
    public int getDigits() {
        return this.generator.getDigits();
    }

    private byte[] periodToBytes(long period) {
        return ByteBuffer.allocate(8).putLong(period).array();
    }
}
