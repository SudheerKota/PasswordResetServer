/*
 * Created by Jaime Chon on 3/7/16.
 */
package io.grvty;

import io.grvty.security.crypto.otp.GCHmacAlgorithm;
import io.grvty.security.crypto.otp.GCOtpGenerator;
import io.grvty.security.crypto.otp.GCTotpCounter;
import io.grvty.security.crypto.otp.GCTotpGenerator;
import io.grvty.security.utils.time.GSecTime;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.*;

@RunWith(Parameterized.class)
public class TotpGeneratorTest {
    private long time;
    private Key key;
    private long t0;
    private long x;
    private int digits;
    private GCHmacAlgorithm hmacAlgorithm;
    private String expectedResult;

    public TotpGeneratorTest(long time, String secret, long t0, long x, int digits, GCHmacAlgorithm hmacAlgorithm, String expectedResult) {
        this.time = time;
        this.key = new SecretKeySpec(secret.getBytes(), hmacAlgorithm.getAlgorithm());
        this.t0 = t0;
        this.x = x;
        this.digits = digits;
        this.hmacAlgorithm = hmacAlgorithm;
        this.expectedResult = expectedResult;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] {
                {59L, "12345678901234567890", 0, 30, 8,  GCHmacAlgorithm.HmacSHA1, "94287082"},
                {59L, "12345678901234567890123456789012", 0, 30, 8, GCHmacAlgorithm.HmacSHA256, "46119246"},
                {59L, "1234567890123456789012345678901234567890123456789012345678901234", 0, 30, 8, GCHmacAlgorithm.HmacSHA512, "90693936"},
                {1111111109L, "12345678901234567890", 0, 30, 8,  GCHmacAlgorithm.HmacSHA1, "07081804"},
                {1111111109L, "12345678901234567890123456789012", 0, 30, 8, GCHmacAlgorithm.HmacSHA256, "68084774"},
                {1111111109L, "1234567890123456789012345678901234567890123456789012345678901234", 0, 30, 8, GCHmacAlgorithm.HmacSHA512, "25091201"},
                {1111111111L, "12345678901234567890", 0, 30, 8,  GCHmacAlgorithm.HmacSHA1, "14050471"},
                {1111111111L, "12345678901234567890123456789012", 0, 30, 8, GCHmacAlgorithm.HmacSHA256, "67062674"},
                {1111111111L, "1234567890123456789012345678901234567890123456789012345678901234", 0, 30, 8, GCHmacAlgorithm.HmacSHA512, "99943326"},
                {1234567890L, "12345678901234567890", 0, 30, 8,  GCHmacAlgorithm.HmacSHA1, "89005924"},
                {1234567890L, "12345678901234567890123456789012", 0, 30, 8, GCHmacAlgorithm.HmacSHA256, "91819424"},
                {1234567890L, "1234567890123456789012345678901234567890123456789012345678901234", 0, 30, 8, GCHmacAlgorithm.HmacSHA512, "93441116"},
                {2000000000L, "12345678901234567890", 0, 30, 8,  GCHmacAlgorithm.HmacSHA1, "69279037"},
                {2000000000L, "12345678901234567890123456789012", 0, 30, 8, GCHmacAlgorithm.HmacSHA256, "90698825"},
                {2000000000L, "1234567890123456789012345678901234567890123456789012345678901234", 0, 30, 8, GCHmacAlgorithm.HmacSHA512, "38618901"},
                {20000000000L, "12345678901234567890", 0, 30, 8,  GCHmacAlgorithm.HmacSHA1, "65353130"},
                {20000000000L, "12345678901234567890123456789012", 0, 30, 8, GCHmacAlgorithm.HmacSHA256, "77737706"},
                {20000000000L, "1234567890123456789012345678901234567890123456789012345678901234", 0, 30, 8, GCHmacAlgorithm.HmacSHA512, "47863826"},
        });
    }

    @Test
    public void testTotpGenerator() {
        GCTotpGenerator generator = new GCTotpGenerator(new GCOtpGenerator(hmacAlgorithm, digits), new GCTotpCounter(t0, x, new GSecTimeConstant(time)));
        String token = generator.generateOtpToken(key);
        assertTrue("TotpGenerator generated the wrong token.", expectedResult.equals(token));
    }

    private class GSecTimeConstant extends GSecTime {
        long seconds;

        GSecTimeConstant(long time) {
            this.seconds = time;
        }

        @Override
        public long currentTimeSeconds() {
            return this.seconds;
        }
    }
}
