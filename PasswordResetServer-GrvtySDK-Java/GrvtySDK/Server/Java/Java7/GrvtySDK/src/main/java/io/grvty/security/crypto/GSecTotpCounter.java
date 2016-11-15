/*
 * Created by Jaime Chon on 3/5/16.
 */
package io.grvty.security.crypto;

public class GSecTotpCounter {
    private static final int MAX_PERIOD_DRIFT = 10;

    private final int minusPeriods;
    private final int plusPeriods;

    public GSecTotpCounter(int minusPeriods, int plusPeriods) {
        if (0 > plusPeriods || MAX_PERIOD_DRIFT < plusPeriods) {
            throw new IllegalArgumentException(
                    String.format("plusX=%s must be a at least 0 and less than %s", plusPeriods, MAX_PERIOD_DRIFT));}
        if (0 > minusPeriods || MAX_PERIOD_DRIFT < minusPeriods) {
            throw new IllegalArgumentException(
                    String.format("minusX=%s must be at least 0 and less than %s", minusPeriods, MAX_PERIOD_DRIFT));}
        this.plusPeriods = plusPeriods;
        this.minusPeriods = minusPeriods;
    }

    /*
     * Get the valid time period offsets for which to check an OTP token. Always returns
     * at least zero indicating the current time period
     * @return array of time period offsets
     */
    /*
     * Get the time periods for which to check an OTP token
     * @return array of time periods
     */
    /*
     * Get the valid TOTP time periods given a time
     * @param count UTC time in seconds
     * @return valid time periods in seconds
     */
    public long[] validTotpCounts(long count) {
        // Possible integer overflow if the requirement for the plus/minus
        // periods to be between 0 and 10 is removed.
        int[] drifts = new int[1 + this.plusPeriods + this.minusPeriods];
        int x = 0;
        drifts[x] = 0;
        for (int i=1; i<=this.plusPeriods; i++) {
            x++;
            drifts[x] = i;
        }
        for (int i=1; i<=this.minusPeriods; i++) {
            x++;
            drifts[x] = -i;
        }

        long[] counts = new long[drifts.length];

        int i = 0;
        for (int offset : drifts) {
            long actualPeriod = Math.max(0, count + offset);
            counts[i] = actualPeriod;
            i++;
        }
        return counts;
    }

    /*
     * check if a given UTC time in seconds falls within the active
     * TOTP time window
     * @param count UTC time in seconds
     * @param window UTC time in seconds
     * @return if time is in OTP time window
     */
    private boolean isPeriodInWindow(long count, long window) {
        for (long offset : validTotpCounts(window)) {
            long actualPeriod = Math.max(0, window + offset);
            if (count == actualPeriod) {
                return true;
            }
        }
        return false;
    }
}
