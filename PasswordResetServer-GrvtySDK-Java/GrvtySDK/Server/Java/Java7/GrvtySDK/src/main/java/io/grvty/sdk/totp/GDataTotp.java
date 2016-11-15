/*
 * Created by Jaime Chon on 3/6/16.
 */
package io.grvty.sdk.totp;

import io.grvty.security.GSecTotpKey;
import io.grvty.security.crypto.Utilities;
import io.grvty.security.crypto.otp.GCHmacAlgorithm;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.ArrayList;
import java.util.List;

/**
 */
public class GDataTotp {
    private static Log log = LogFactory.getLog(GDataTotp.class);
    /**
     * Host applications are required to implement this data interface.
     * This interface provides access to user accounts stored with
     * the database for the GRVTY system.
     */
    public interface GTAccountInterface {
        /**
         * Get a List of all devices registered to this account
         * @return user's registered devices
         */
        List<GTKeyInterface> getKeys();

        /**
         * Add a token attempting a validation attempt to the account
         * @param period the current time step
         * @param token the token that was used for the validation attempt
         * @param valid if the token was successfully validated
         */
        boolean addOtpToken(long period, String token, boolean valid);
    }

    /**
     * Host applications are required to implement this data interface.
     * This interface provides access to registered devices stored with
     * the database for the GRVTY system.
     */
    public interface GTKeyInterface {
        /**
         * Get the unique account id that this device is registered to
         * @return the account id (e.g. username)
         */
        byte[] getUniqueVal();

        /**
         * Get the encrypted device secret key
         * @return encrypted secret key
         */
        byte[] getOtpKey();
    }

    private final byte[] appSecret;
    GCHmacAlgorithm hmacAlgorithm;

    public GDataTotp(byte[] appSecret, GCHmacAlgorithm hmacAlgorithm) {
        if (appSecret == null) {
            throw new IllegalArgumentException("byte[] appSecret must not be null.");
        }
        if (hmacAlgorithm == null) {
            throw new IllegalArgumentException("GCHmacAlgorithm hmacAlgorithm must not be null");
        }
        if (appSecret.length != hmacAlgorithm.getDigestLength()) {
            throw new IllegalArgumentException(String.format("byte[] appSecret length is %s. Must be equal to the hmac digest length %s", appSecret.length, hmacAlgorithm.getDigestLength()));
        }
        this.appSecret = appSecret;
        this.hmacAlgorithm = hmacAlgorithm;
    }

    public byte[] wrapKey(byte[] key) {
        if (key == null) {
            throw new IllegalArgumentException("byte[] appSecret must not be null.");
        }
        if (key.length != this.appSecret.length) {
            throw new IllegalArgumentException(String.format("byte[] key length is %s must be equal to the hmac digest length %s.", key.length, this.appSecret.length));
        }
        return Utilities.secureKey(this.appSecret, key);
    }

    public List<GSecTotpKey> unwrapDevices(List<GTKeyInterface> totpKeys) {
        List<GSecTotpKey> result = new ArrayList<>();
        for (GTKeyInterface gtKey : totpKeys) {
            Key key = new SecretKeySpec(Utilities.unwrapKey(this.appSecret, gtKey.getOtpKey()), this.hmacAlgorithm.getAlgorithm());
            byte[] accountId = gtKey.getUniqueVal();
            result.add(new GSecTotpKey(key, accountId));
        }
        return result;
    }
}
