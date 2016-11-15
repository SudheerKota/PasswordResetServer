/*
 * Created by Jaime Chon on 1/30/16.
 */
package io.grvty.security.crypto.otp;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.crypto.Mac;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Arrays;

/**
 * Generic OTP generator. It is the main building block to create
 * a TOTP and/or HOTP generator.
 */
public class GCOtpGenerator {
    private static Log log = LogFactory.getLog(GCOtpGenerator.class);
    private static final int[] DIGITS_POWER
            // 0  1   2    3     4      5       6        7         8          9
            = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000};

    private final GCHmacAlgorithm hmac;
    private final int digits;

    /**
     * The default initializer for the OTP generator. This generator is compliant with
     * RFC 4226.
     * @param hmac HMAC algorithm to use to generate tokens
     * @param digits the length of the output token
     */
    public GCOtpGenerator(GCHmacAlgorithm hmac, int digits) {
        if (hmac == null) {
            throw new IllegalArgumentException("GCHmacAlgorithm must not be null.");
        }
        if (digits < 5 || digits > 10) {
            throw new IllegalArgumentException(String.format("int digits is %s. must be between 5 and 11.", digits));
        }
        this.hmac = hmac;
        this.digits = digits;
    }

    /**
     * Generate an OTP token using the configured parameters
     * @throws GeneralSecurityException if an error occurred with the cryptographic function
     * @param key OTP key
     * @param data data to hash
     * @return generated OTP token
     */
    public String generateOtp(Key key, byte[] data) throws GeneralSecurityException {
        if (key == null) {
            throw new IllegalArgumentException("Key key can't be null.");
        }
        if (data == null) {
            throw new IllegalArgumentException("data[] data can't be null");
        }
        if (key.getEncoded().length != this.hmac.getDigestLength()) {
            throw new IllegalArgumentException(String.format("Key length is %s bytes. Must be %s bytes.", key.getEncoded().length, this.hmac.getDigestLength()));
        }
        if (data.length < 8){
            throw new IllegalArgumentException(String.format("byte[] data is %s bytes. Must be at least 8 bytes.", data.length));
        }
        Mac hmac = Mac.getInstance(this.hmac.getAlgorithm());
        hmac.init(key);
        byte[] hash = hmac.doFinal(data);

        // Converts a generated OTP hash into a token
        if (hash.length != this.hmac.getDigestLength()) {
            throw new IllegalArgumentException("Invalid TOTP hash length");
        }
        int offset = hash[hash.length - 1] & 0xf;
        int hashTruncated = ((hash[offset] & 0x7f) << 24) |
                ((hash[offset + 1] & 0xff) << 16) |
                ((hash[offset + 2] & 0xff) << 8) |
                (hash[offset + 3] & 0xff);
        int token = hashTruncated % DIGITS_POWER[this.digits];
        String result = Integer.toString(token);
        // left pad with "0" if shorter than desired length
        while (result.length() < this.digits) {
            result = "0" + result;
        }
        log.trace(String.format("OTP(alg=%s, tLen=%s, key=%s, data=%s)=%s", this.hmac, this.digits, key, Arrays.toString(data), result));
        return result;
    }

    /**
     * Get the number of digits that the OTP generator will return
     * @return length of OTP token
     */
    public int getDigits() {
        return this.digits;
    }
}
