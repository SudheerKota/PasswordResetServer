/*
 * Created by Jaime Chon on 1/30/16.
 */
package io.grvty.security;

import io.grvty.security.crypto.GSecTotpCounter;
import io.grvty.security.crypto.Utilities;
import io.grvty.security.crypto.otp.GCTotpGenerator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.regex.Pattern;

/**
 * The main class that will validate Tokens. This class will validate
 * tokens based on the given configuration.
 */
public class GSecOtpValidator {
    private static Log log = LogFactory.getLog(GSecOtpValidator.class);
    private final static Pattern patternToken = Pattern.compile("[0-9]+");

    private final GCTotpGenerator generator;
    private final GSecTotpCounter totpCounter;

    public GSecOtpValidator(GCTotpGenerator generator, GSecTotpCounter totpCounter) {
        this.generator = generator;
        this.totpCounter = totpCounter;
    }

    /**
     * The default initializer.
     * @param generator the configured GCTotpGenerator to use to generate tokens
     * @param minusX the number of past time steps that are still valid. Default: 1
     * @param plusX the number of future time steps that are currently valid. Default: 1
     */
    public GSecOtpValidator(GCTotpGenerator generator, int minusX, int plusX) {
        this(generator, new GSecTotpCounter(minusX, plusX));
    }

    /**
     * validate a user provided OTP token
     * @throws GeneralSecurityException if an error occurred with the cryptographic function
     * @param gSecTotpKey OTP key
     * @param token OTP token to validate
     * @param time time
     * @return true/false if token is valid
     */
    public boolean validateOtpToken(GSecTotpKey gSecTotpKey, String token, long time) throws GeneralSecurityException {
        if (token.length() != this.generator.getDigits()) {
            log.trace(String.format("Token length is %s. Must be %s", token.length(), this.generator.getDigits()));
            return false;
        }
        if (!patternToken.matcher(token).matches()) {
            log.info(String.format("Token:\"%s\" must be all digits without any spaces", token));
            return false;
        }
        // validate user otp token
        for (long count : this.totpCounter.validTotpCounts(time)) {
            Key key = gSecTotpKey.getKey();
            byte[] user = gSecTotpKey.getUnique();
            byte[] period = Utilities.join(user, periodToBytes(count));
            String tokenGenerated = generator.generateOtpToken(key, period);
            boolean equalConstantTime = Utilities.isEqualConstantTime(tokenGenerated, token);
            log.trace(String.format("OTPTokenValidation(key=%s, token=%s, period=%s)=%s", gSecTotpKey, token, count, equalConstantTime ? "SUCCEEDED" : "FAILED"));
            if (equalConstantTime) {
                return true;
            }
        }
        log.trace(String.format("validation failed for key:%s", gSecTotpKey));
        return false;
    }

    /**
     * Get the length of generated OTP tokens
     * @return OTP token length
     */
    public int getDigits() {
        return this.generator.getDigits();
    }

    /**
     * Convert a time period into bytes
     * @param period otp time period
     * @return period in bytes
     */
    private byte[] periodToBytes(long period) {
        return ByteBuffer.allocate(8).putLong(period).array();
    }
}
