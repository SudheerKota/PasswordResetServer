/*
 * Created by Jaime Chon on 3/5/16.
 */
package io.grvty.security.alerts;

/**
 * A GRVTY security alert
 */
public class GSecAlert {
    private final String level;
    private final String domain;
    private final String alert;
    private final String description;

    public GSecAlert(String level, String domain, String alert, String description) {
        this.level = level;
        this.domain = domain;
        this.alert = alert;
        this.description = description;
    }

    /*
     * G
     * @return
     */
    private String getLevel() {
        return level;
    }

    /*
     *
     * @return
     */
    private String getDomain() {
        return domain;
    }

    /**
     * Get the type of security alert
     * @return alert type
     */
    public String getAlert() {
        return alert;
    }

    /**
     * Get a description of the alert
     * @return description
     */
    public String getDescription() {
        return description;
    }
}
