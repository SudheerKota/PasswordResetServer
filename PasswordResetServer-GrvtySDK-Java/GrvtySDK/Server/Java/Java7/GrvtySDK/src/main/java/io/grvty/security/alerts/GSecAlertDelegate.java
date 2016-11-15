/*
 * Created by Jaime Chon on 1/31/16.
 */
package io.grvty.security.alerts;

/**
 * The interface for handling detected security alerts
 */
public interface GSecAlertDelegate {
    /**
     * Handle security alert
     * @param alert security alert
     */
    void securityAlert(GSecAlert alert);
}
