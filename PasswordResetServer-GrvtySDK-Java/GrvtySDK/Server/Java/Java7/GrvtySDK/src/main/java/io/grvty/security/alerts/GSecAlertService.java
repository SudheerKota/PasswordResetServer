/*
 * Created by Jaime Chon on 1/31/16.
 */
package io.grvty.security.alerts;

/**
 * The central switchboard to dispatch security alerts detected by the GRVTY system.
 */
public class GSecAlertService {
    private static GSecAlertDelegate securityAlertDelegate;

    // prevent the class from being instantiated
    private GSecAlertService() {}

    /**
     * Set the delegate that is going to receive the security alerts.
     * @param delegate object that implements the GSecAlertDelegate interface.
     */
    public static void setSecurityAlertDelegate(GSecAlertDelegate delegate) {
        securityAlertDelegate = delegate;
    }

    /**
     * Remove the registered security alert delegate
     */
    public static void removeSecurityAlertDelegate() {
        securityAlertDelegate = null;
    }

    /**
     * Get the currently set GrvtySecurityAlert delegate. If no
     * delegate has been set, then a no-op delegate is returned.
     * @return current delegate
     */
    public static GSecAlertDelegate getSecurityAlertDelegate() {
        if (securityAlertDelegate == null) {
            // create a null security alert delegate
            securityAlertDelegate = new GSecAlertDelegate() {
                @Override
                public void securityAlert(GSecAlert alert) {}
            };
        }
        return securityAlertDelegate;
    }

    public static boolean isAlertDelegateSet() {
        return securityAlertDelegate != null;
    }
}
