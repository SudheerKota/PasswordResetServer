/*
 * Created by Jaime Chon on 3/6/16.
 */
package io.grvty.sdk.totp;

import static io.grvty.sdk.totp.GDataTotp.*;
import io.grvty.security.GSecOtpValidator;
import io.grvty.security.GSecTotpKey;
import io.grvty.security.crypto.otp.GCHmacAlgorithm;
import io.grvty.security.crypto.otp.GCTotpCounter;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.security.GeneralSecurityException;
import java.util.List;
import java.util.regex.Pattern;

public class TotpValidator {
    private static Log log = LogFactory.getLog(TotpValidator.class);
    /*
     * A general TOTP token validator. Checks if the token has at least
     * 1 digit and is composed of only digits.
     */
    private final static Pattern patternToken = Pattern.compile("[0-9]+");

    private final GSecOtpValidator validator;
    private final GDataTotp totpDataRepository;
    private final GCTotpCounter totpCounter;

    public TotpValidator(GSecOtpValidator validator, GDataTotp totpDataRepository, GCTotpCounter totpCounter) {
        if (validator == null) { throw new IllegalArgumentException("GSecOtpValidator validator must not be null"); }
        if (totpDataRepository == null) { throw new IllegalArgumentException("GDataTotp totpDataRepository must not be null"); }
        if (totpCounter == null) { throw new IllegalArgumentException("GCTotpCounter totpCounter must not be null"); }
        this.validator = validator;
        this.totpDataRepository = totpDataRepository;
        this.totpCounter = totpCounter;
    }

    /**
     * Check if a TOTP token is valid
     * @param account the account to check the TOTP token for
     * @param token user provided TOTP token
     * @return true if the user provided TOTP token is valid, false if otherwise
     */
    public boolean validateOtpToken(GTAccountInterface account, String token) throws GeneralSecurityException {
        log.trace(String.format("Validating token: %s with account: %s", token, account));
        if (account == null) {
            throw new IllegalArgumentException("GTAccountInterface must not be null");
        }
        if (token == null) {
            log.trace(String.format("Validation failed due to token being null"));
            return false;
        }
        if (token.length() != this.validator.getDigits()) {
            log.trace(String.format("Validation failed due to token being the wrong size. Token length is %s. Must be %s", "", token.length(), this.validator.getDigits()));
            return false;
        }
        if (!patternToken.matcher(token).matches()) {
            log.trace(String.format("Validation failed due to token containing an invalid character"));
            return false;
        }

        long time = this.totpCounter.totpCount();
        boolean valid = false;
        List<GSecTotpKey> gSecTotpKeys = this.totpDataRepository.unwrapDevices(account.getKeys());
        log.trace(String.format("%s keys (devices) found for account: %s", gSecTotpKeys.size(), account));
        for (GSecTotpKey device : gSecTotpKeys) {
            boolean b = this.validator.validateOtpToken(device, token, time);
            log.trace(String.format("Validation for device:%s, token:%s, time:%s. %s", device, token, time, b ? "SUCCEEDED" : "FAILED"));
            if (b) {
                valid = true;
                break;
            }
        }
        log.debug(String.format("token validation: %s", valid ? "SUCCESS" : "FAIL"));
        valid = account.addOtpToken(time, token, valid) && valid;
        log.debug(String.format("adding token to database: %s", valid ? "SUCCESS" : "FAIL"));
        return valid;
    }

    public byte[] wrapKey(byte[] key) {
        if (key == null) {
            throw new IllegalArgumentException("Key must not be null");
        }
        return this.totpDataRepository.wrapKey(key);
    }

    /**
     * Get the TOTP Counter
     * @return GCTotpCounter
     */
    public GCTotpCounter getTotpCounter() {
        return totpCounter;
    }

    /**
     * Get the configured period length
     * @return TOTP time step
     */
    public long getPeriodLength() {
        return totpCounter.getPeriodLength();
    }
}
