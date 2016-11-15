/*
 * Created by Jaime Chon on 3/5/16.
        The getCurrentSecond method does not check if the time value in milliseconds returned by

the operating system changed since the last call. Attackers can find a way to fix the

system's time value, for example abusing vulnerabilities in the operating system or

virtualization environment of the server. Old tokens can be reused and brute-force attacks

can be facilitated if the server time can be fixed to a known value.
// TODO: Verify that time moves forward. Use only secure protocols for time synchronization with remote trusted servers. Detect and report inconsistencies.
NTP MiTM attack using Delorean
http://www.en.pentester.es/2015/10/delorean.html

Bypassing WordPress Login Pages with WPBiff
https://blog.gaborszathmari.me/2015/11/11/bypassing-wordpress-login-pages-with-wpbiff/
https://blog.gaborszathmari.me/2015/11/11/bypassing-wordpress-login-pages-with-wpbiff/tripelover-crontab/
https://blog.gaborszathmari.me/2015/11/11/tricking-google-authenticator-totp-with-ntp/
https://bugzilla.redhat.com/show_bug.cgi?id=1271076
 */
package io.grvty.security.utils.time;

public class GSecTime {
    private static final long MILLIS_IN_SECONDS = 1000;  // # of milliseconds in a second

    private long lastKnownTime;

    public GSecTime() {
        lastKnownTime = System.currentTimeMillis();
    }

    /**
     * Get the current UTC system time in seconds
     * @return seconds since epoch (January 1, 1970)
     */
    public long currentTimeSeconds() {
        // Get the current time in seconds since Epoch time (January 1, 1970)
        long milliSeconds = System.currentTimeMillis();
        /* TODO
        should be ">=", but can't do this without a major rework, since calls will
        need to be batched.
        This will also be a major issue when dealing with multiple threads. E.g.
        two validations might need to be performed at the same time.
         */
        if (lastKnownTime > milliSeconds) {
//        if (lastKnownTime >= milliSeconds) {
            GSecTimeAlert.systemTimeRegression();
        } else {
            lastKnownTime = milliSeconds;
        }
        return milliSeconds / MILLIS_IN_SECONDS;
    }
}
