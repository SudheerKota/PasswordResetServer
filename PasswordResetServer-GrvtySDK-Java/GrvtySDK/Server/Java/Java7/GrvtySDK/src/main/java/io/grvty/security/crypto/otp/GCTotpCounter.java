/*
 * Created by Jaime Chon on 3/5/16.
 */
package io.grvty.security.crypto.otp;

import io.grvty.security.utils.time.GSecTime;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class GCTotpCounter {
    private static Log log = LogFactory.getLog(GCTotpCounter.class);
    private final long initialTime;  // must be at least zero
    private final long periodLength;  // must be a positive integer
    private GSecTime clock;

    /*
     * Initializer for GCTotpGenerator.
     * @param initialTime initial time (other than January 1, 1970). must be at least 0
     * @param periodLength the length of a time period. must be a positive integer
     */
    public GCTotpCounter(long initialTime, long periodLength, GSecTime clock) {
        if (0 > initialTime) {
            throw new IllegalArgumentException(String.format("long initialTime is %s. Must be positive.", initialTime));
        }
        if (0 >= periodLength && 600 < periodLength) {
            throw new IllegalArgumentException(String.format("long periodLength is %s. Must be between 0 and 601", periodLength));
        }
        this.clock = clock == null ? new GSecTime() : clock;
        this.initialTime = initialTime;
        this.periodLength = periodLength;
    }

    public GCTotpCounter(long initialTime, long periodLength) {
        this(initialTime, periodLength, null);
    }

    /*
     * Get the current TOTP time period
     * @return time period
     */
    public long totpCount() {
        return totpCount(this.clock.currentTimeSeconds());
    }

    /*
     * Convert seconds into an TOTP time period
     * @param seconds current seconds since epoch (January 1, 1970)
     * @return otp time period
     */
    public long totpCount(long seconds) {
        if (seconds < 0) {
            throw new IllegalArgumentException(String.format("long seconds is %s. Must be >= 0", seconds));
        }

        long period;
        long adjustedTime = seconds - this.initialTime;
        if (adjustedTime >= 0) {
            period = adjustedTime / this.periodLength;
        } else {
            period = (adjustedTime - (this.periodLength - 1)) / this.periodLength;
        }
        log.trace(String.format("TOTPCount(time=%s, t0=%s, x=%s)=%s", seconds, this.initialTime, this.periodLength, period));
        return period;
    }

    public long getPeriodLength() {
        return periodLength;
    }
}
