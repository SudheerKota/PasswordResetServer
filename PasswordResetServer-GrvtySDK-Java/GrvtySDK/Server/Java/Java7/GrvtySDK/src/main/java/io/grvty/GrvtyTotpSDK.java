/*
 * Created by Jaime Chon on 1/9/16.
 * todo: Secure time synchronization protocols need to be used.
 */
package io.grvty;

import io.grvty.sdk.totp.GDataTotp;
import io.grvty.sdk.totp.TotpValidator;
import io.grvty.security.GSecOtpValidator;
import io.grvty.security.alerts.*;
import io.grvty.security.crypto.GSecTotpCounter;
import io.grvty.security.crypto.otp.GCHmacAlgorithm;
import io.grvty.security.crypto.otp.GCOtpGenerator;
import io.grvty.security.crypto.otp.GCTotpCounter;
import io.grvty.security.crypto.otp.GCTotpGenerator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


/**
 * The main interface the GRVTY Password Reset System Server SDK to validate OTP tokens.
 */
public class GrvtyTotpSDK {
    private static Log log = LogFactory.getLog(GrvtyTotpSDK.class);

    private static final long DEFAULT_START_TIME = 0;  // must be at least zero
    private static final long DEFAULT_PERIOD = 30;  // must be a positive integer

    private static final int DEFAULT_DIGITS = 8;
    private static final int DEFAULT_PERIOD_PLUS = 1;
    private static final int DEFAULT_PERIOD_MINUS = 1;

    private byte[] appSecret;
    private long epochStart;
    private long periodLength;
    private int tokenLength;
    private int previousPeriods;
    private int nextPeriods;
    private GCHmacAlgorithm hmacAlgorithm;

    /**
     * The default initializer. The system requires an app secret to be set to be
     * able to encrypt/decrypt TOTP keys. This initializer has the following defaults:
     * - long epochStart: 0
     * - long periodLength: 30
     * - int tokenLength: 8
     * - int previousPeriods: 1
     * - int nextPeriods: 1
     * - GCHmacAlgorithm hmacAlgorithm: HmacSHA256
     * @param appSecret application key
     */
    public GrvtyTotpSDK(byte[] appSecret) {
        if (appSecret == null) {
            throw new IllegalArgumentException("byte[] appSecret must not be null");
        }
        if (appSecret.length < 1) {
            throw new IllegalArgumentException("byte[] appSecret length must be greater than 0");
        }
        this.appSecret = appSecret;
        this.epochStart = DEFAULT_START_TIME;
        this.periodLength = DEFAULT_PERIOD;
        this.tokenLength = DEFAULT_DIGITS;
        this.previousPeriods = DEFAULT_PERIOD_MINUS;
        this.nextPeriods = DEFAULT_PERIOD_PLUS;
        this.hmacAlgorithm = GCHmacAlgorithm.DEFAULT;
    }

    /**
     * From the chosen configuration build the GRVTY TOTP Validation System
     * @return token validator
     */
    public TotpValidator build() {
        if (!GSecAlertService.isAlertDelegateSet()) {
            throw new IllegalArgumentException("The security alert delegate must be set. Use GrvtyTotpSDK.setGrvtySecurityAlertDelegate(...)");
        }
        if (this.hmacAlgorithm == null) {
            throw new IllegalArgumentException("GCHmacAlgorithm hmacAlgorithm must not be null.");
        }
        if (this.appSecret == null) {
            throw new IllegalArgumentException("byte[] appSecret must not be null.");
        }
        if (appSecret.length != hmacAlgorithm.getDigestLength()) {
            throw new IllegalArgumentException(
                    String.format("length of appSecret=%s must equal the digestLength=%s", appSecret.length, hmacAlgorithm.getDigestLength()));
        }
        if (this.epochStart < 0) {
            throw new IllegalArgumentException(String.format("long epochStart is %s. Must be a non-negative number.", this.epochStart));
        }
        if (this.periodLength < 1 || this.periodLength > 600) {
            throw new IllegalArgumentException(String.format("long periodLength is %s. Must be between 0 and 601.", this.periodLength));
        }
        if (this.tokenLength < 5 || this.tokenLength > 10) {
            throw new IllegalArgumentException(String.format("int tokenLength is %s. Must be between 4 and 11.", this.tokenLength));
        }
        if (this.previousPeriods < 0 || this.previousPeriods > 10) {
            throw new IllegalArgumentException(String.format("int previousPeriods is %s. Must be between -1 and 11.", this.previousPeriods));
        }
        if (this.nextPeriods < 0 || this.nextPeriods > 10) {
            throw new IllegalArgumentException(String.format("int nextPeriods is %s. Must be between -1 and 11.", this.nextPeriods));
        }

        GCOtpGenerator generator1 = new GCOtpGenerator(this.hmacAlgorithm, this.tokenLength);
        GCTotpCounter totpCounter = new GCTotpCounter(this.epochStart, this.periodLength);
        GCTotpGenerator generator = new GCTotpGenerator(generator1, totpCounter);
        GSecTotpCounter totpCounter1 = new GSecTotpCounter(this.previousPeriods, this.nextPeriods);
        GSecOtpValidator validator = new GSecOtpValidator(generator, totpCounter1);
        GDataTotp totpDataRepository = new GDataTotp(this.appSecret, hmacAlgorithm);
        TotpValidator totpValidator = new TotpValidator(validator, totpDataRepository, totpCounter);
        Package aPackage = GrvtyTotpSDK.class.getPackage();
        String version = String.format("%s:%s:%s", aPackage.getImplementationVendor(), aPackage.getImplementationTitle(), aPackage.getImplementationVersion());
        String hmacAlgorithmName = String.format("HmacSHA%s", appSecret.length * 8);
        String parameters = String.format("appSecret=byte[%s] {...}, hmacAlgorithm=%s, tokenLength=%s, epochStart=%s, periodLength=%s, previousPeriods=%s, nextPeriods=%s", appSecret.length, hmacAlgorithmName, tokenLength, epochStart, periodLength, previousPeriods, nextPeriods);
        log.info(String.format("%s created new TotpValidator with parameters: %s", version, parameters));
        return totpValidator;
    }

    /**
     * Set GSecAlertDelegate. The delegate is used to receive security alerts
     * generated by the GrvtyTotpSDK at runtime.
     * @param delegate GSecAlertDelegate
     */
    public static void setGrvtySecurityAlertDelegate(GSecAlertDelegate delegate) {
        if (delegate == null) {
            throw new IllegalArgumentException("GSecAlertDelegate delegate must not be null");
        }
        GSecAlertService.setSecurityAlertDelegate(delegate);
    }

    /**
     * Set the start time that the validation system should use. The start
     * time is specified as a positive integer representing an offset from
     * the reference time. Zero represents the reference time of the start
     * of Epoch (January 1, 1970)
     * @param epochStart start time in seconds since epoch
     */
    public void setEpochStart(long epochStart) {
        if (this.epochStart < 0) {
            throw new IllegalArgumentException(String.format("long epochStart is %s. Must be a non-negative number.", this.epochStart));
        }
        this.epochStart = epochStart;
    }

    /**
     * Time in seconds that a token should be valid for.
     * @param periodLength the length of a time interval
     */
    public void setPeriodLength(long periodLength) {
        if (this.periodLength < 1 || this.periodLength > 600) {
            throw new IllegalArgumentException(String.format("long periodLength is %s. Must be between 0 and 601.", this.periodLength));
        }
        this.periodLength = periodLength;
    }

    /**
     * The length of a generated token
     * @param tokenLength length of generated tokens
     */
    public void setTokenLength(int tokenLength) {
        if (this.tokenLength < 5 || this.tokenLength > 10) {
            throw new IllegalArgumentException(String.format("int tokenLength is %s. Must be between 4 and 11.", this.tokenLength));
        }
        this.tokenLength = tokenLength;
    }

    /**
     * Time window
     * @param previousPeriods number of past periods to check
     */
    public void setPreviousPeriods(int previousPeriods) {
        if (this.previousPeriods < 0 || this.previousPeriods > 10) {
            throw new IllegalArgumentException(String.format("int previousPeriods is %s. Must be between -1 and 11.", this.previousPeriods));
        }
        this.previousPeriods = previousPeriods;
    }

    /**
     * Time window
     * @param nextPeriods number of future periods to check
     */
    public void setNextPeriods(int nextPeriods) {
        if (this.nextPeriods < 0 || this.nextPeriods > 10) {
            throw new IllegalArgumentException(String.format("int nextPeriods is %s. Must be between -1 and 11.", this.nextPeriods));
        }
        this.nextPeriods = nextPeriods;
    }

    /**
     * HmacAlgorithm
     * @param hmacAlgorithm hmac algorithm
     */
    public void setHmacAlgorithm(GCHmacAlgorithm hmacAlgorithm) {
        if (this.hmacAlgorithm == null) {
            throw new IllegalArgumentException("GCHmacAlgorithm hmacAlgorithm must not be null.");
        }
        this.hmacAlgorithm = hmacAlgorithm;
    }

    /**
     * Set the app secret
     * @param appSecret app secret
     */
    public void setAppSecret(byte[] appSecret) {
        if (this.appSecret == null) {
            throw new IllegalArgumentException("byte[] appSecret must not be null.");
        }
        this.appSecret = appSecret;
    }
}