/*
 * Created by Jaime Chon on 3/7/16.
 */
package io.grvty.security;

import java.security.Key;

public class GSecTotpKey {
    private final Key key;
    private final byte[] unique;

    public GSecTotpKey(Key key, byte[] unique) {
        this.key = key;
        this.unique = unique;
    }

    public Key getKey() {
        return key;
    }

    public byte[] getUnique() {
        return unique;
    }
}
