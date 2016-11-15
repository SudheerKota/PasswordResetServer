/*
 * Created by Jaime Chon on 3/5/16.
 */
package io.grvty.security.utils.time;

import io.grvty.security.alerts.GSecAlert;
import io.grvty.security.alerts.GSecAlertService;

/**
 * Report security alerts detected by the GRVTY TOTP system.
 */
class GSecTimeAlert {
    /**
     * Create new alert to report that system time has regressed
     * from last known value or did not change
     * between subsequent calls of the system time.
     */
    static void systemTimeRegression() {
        sendSecurityAlert(new GSecAlert("CRITICAL", "io.grvty.security.crypto.otp", "systemTimeRegression", "systemTimeRegression"));
    }

    /**
     * Create new alert to report that system time did not change
     * between subsequent calls of the system time.
     */
    static void systemTimeStall() {
        sendSecurityAlert(new GSecAlert("CRITICAL", "io.grvty.security.crypto.otp", "systemTimeStall", "systemTimeStall"));
    }

    /*
     * convenience method to dispatch a TOTP security alert
     */
    private static void sendSecurityAlert(GSecAlert alert) {
        GSecAlertService.getSecurityAlertDelegate().securityAlert(alert);
    }
}
