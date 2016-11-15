/*
 * Created by Jaime Chon on 3/4/16.
 */
package io.grvty;

import io.grvty.sdk.totp.TotpValidator;
import io.grvty.security.alerts.GSecAlert;
import io.grvty.security.alerts.GSecAlertDelegate;
import io.grvty.security.crypto.Utilities;
import io.grvty.security.crypto.otp.GCHmacAlgorithm;
import io.grvty.security.crypto.otp.GCOtpGenerator;
import io.grvty.security.crypto.otp.GCTotpCounter;
import io.grvty.security.crypto.otp.GCTotpGenerator;
import static io.grvty.sdk.totp.GDataTotp.*;

import io.grvty.security.utils.time.GSecTime;
import org.junit.Test;

import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.*;

import static org.junit.Assert.*;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class GrvtySDKTests {
    private static Log log = LogFactory.getLog(GrvtyTotpSDK.class);

    private class TotpKey implements GTKeyInterface {
        private final byte[] key;
        private final byte[] unique;

        TotpKey(byte[] key, byte[] unique) {
            this.key = key;
            this.unique = unique;
        }

        @Override
        public byte[] getUniqueVal() {
            return this.unique;
        }

        @Override
        public byte[] getOtpKey() {
            return this.key;
        }
    }

    private class TotpToken {
        private final long period;
        private final String token;
        private final boolean valid;

        TotpToken(long period, String token, boolean valid) {
            this.period = period;
            this.token = token;
            this.valid = valid;
        }

        long getPeriod() {
            return this.period;
        }

        String getToken() {
            return this.token;
        }

        boolean isValid() {
            return this.valid;
        }
    }

    private class Account implements GTAccountInterface {
        private final String username;
        private final List<GTKeyInterface> keys;
        private final List<TotpToken> tokens;

        Account(String username) {
            this.username = username;
            this.keys = new ArrayList<>();
            this.tokens = new ArrayList<>();
        }

        void addTotpKey(byte[] key) {
            this.keys.add(new TotpKey(key, this.username.getBytes()));
        }

        @Override
        public List<GTKeyInterface> getKeys() {
            return this.keys;
        }

        @Override
        public boolean addOtpToken(long period, String token, boolean valid) {
            boolean retValid = true;
            if (valid) {
                for (TotpToken t : this.tokens) {
                    if (t.getPeriod() == period && t.getToken().equals(token) && t.isValid()) {
                        retValid = false;
                    }
                }
            }
            this.tokens.add(new TotpToken(period, token, valid));
            return retValid;
        }
    }

    private class Database {
        private Map<String, Account> data;

        Database() {
            this.data = new HashMap<>();
        }

        Account getAccount(String username) {
            return this.data.get(username);
        }

        void addAccount(String username) {
            this.data.put(username, new Account(username));
        }
    }

    private byte[] periodToBytes(long period) {
        return ByteBuffer.allocate(8).putLong(period).array();
    }

    class GSecTimeConstant extends GSecTime {
        long seconds;

        GSecTimeConstant(long time) {
            this.seconds = time;
        }

        @Override
        public long currentTimeSeconds() {
            return this.seconds;
        }
    }

//    @Rule
//    public final ExpectedException exception = ExpectedException.none();

    @Test
    public void testGrvtySDK() {
        byte[] appSecret = "supersecretapplicationserverkey!".getBytes();
        Database database = new Database();
        GrvtyTotpSDK sdk = new GrvtyTotpSDK(appSecret);
        TotpValidator totpValidator;
//        boolean exception = false;

        // Check for security alert exception not set
//        exception.expect(IllegalArgumentException.class);
//        totpValidator = sdk.build();
//        try {
//            totpValidator = sdk.build();
//        } catch (IllegalArgumentException e) {
//            exception = true;
//        }
//        assertTrue("1", exception);
//        exception = false;

        GrvtyTotpSDK.setGrvtySecurityAlertDelegate(new GSecAlertDelegate() {
            @Override
            public void securityAlert(GSecAlert alert) {
                log.error(alert);
            }
        });
        totpValidator = sdk.build();

        // create new account "user 1"
        String username1 = "user_1234567890";
        database.addAccount(username1);
        Account user1 = database.getAccount(username1);
        Key key = new SecretKeySpec("12345678901234567890123456789012".getBytes(), GCHmacAlgorithm.HmacSHA256.getAlgorithm());
        user1.addTotpKey(totpValidator.wrapKey(key.getEncoded()));

        GCTotpCounter totpCounter = new GCTotpCounter(0, 30);
        GCTotpGenerator generator = new GCTotpGenerator(new GCOtpGenerator(GCHmacAlgorithm.HmacSHA256, 8), totpCounter);
        byte[] period = Utilities.join("user_1234567890".getBytes(), periodToBytes(totpCounter.totpCount()));

        String token = generateToken(generator, key, period);
        boolean valid = validateToken(totpValidator, user1, token);
        assertTrue("GrvtySDK is wrong.", valid);

        valid = validateToken(totpValidator, user1, token);
        assertFalse("Token attacks allowed.", valid);
    }

    private String generateToken(GCTotpGenerator generator, Key key, byte[] data) {
        String token = null;
        try {
            token = generator.generateOtpToken(key, data);
        } catch (GeneralSecurityException ignored) {}
        return token;
    }

    private boolean validateToken(TotpValidator totpValidator, GTAccountInterface account, String token) {
        boolean valid = false;
        try {
            valid = totpValidator.validateOtpToken(account, token);
        } catch (GeneralSecurityException ignored) {}
        return valid;
    }

    @Test
    public void testEqual() {
        log.error(Utilities.isEqualConstantTime(null, "hello"));
    }
}
