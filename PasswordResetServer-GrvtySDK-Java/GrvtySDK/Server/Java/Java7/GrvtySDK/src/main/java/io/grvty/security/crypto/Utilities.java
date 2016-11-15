/*
 * Created by Jaime Chon on 3/5/16.
 */
package io.grvty.security.crypto;

public class Utilities {
    /*
     * Constant-time string comparison function to mitigate side channel attack (timing attack).
     * @param a String
     * @param b String
     * @return if a and b are equal
     */
    public static boolean isEqualConstantTime(String a, String b) {
        if (a == null) {
            throw new NullPointerException("String a must not be null.");
        }
        if (b == null) {
            throw new IllegalArgumentException("String b must not be null.");
        }
        if (a.length() != b.length()) {
            return false;
        }

        int result = 0;
        int aLength = a.length();
        for (int i = 0; i < aLength; i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }

    /*
     * Join two byte arrays. Specifically the device uniqueID (accountID)
     * and a TOTP time period
     * @param uniqueId unique accountID
     * @param period TOTP time period
     * @return concatenated uniqueId and period
     */
    public static byte[] join(byte[] uniqueId, byte[] period) {
        if (uniqueId == null) {throw new NullPointerException("byte[] uniqueId must not be null.");}
        if (period == null) {throw new NullPointerException("byte[] period must not be null.");}
        if (period.length != 8) {throw new IllegalArgumentException("Invalid period length");}
        if (uniqueId.length == 0) {throw new IllegalArgumentException("Invalid uniqueId length");}
        byte[] data = new byte[uniqueId.length + period.length];
        System.arraycopy(period, 0, data, 0, period.length);
        System.arraycopy(uniqueId, 0, data, period.length, uniqueId.length);
        return data;
    }

    /*
     * xor of two byte arrays. Specifically it will xor each corresponding
     * byte and return the result. The two arrays must be of equal size.
     * @param a byte array
     * @param b byte array
     * @return xor'ed byte array
     */
    public static byte[] xor(byte[] a, byte[] b) {
        if (a == null) {throw new NullPointerException("byte[] uniqueId must not be null.");}
        if (b == null) {throw new NullPointerException("byte[] period must not be null.");}
        if (a.length != b.length) {
            throw new IllegalArgumentException(String.format("a.length=%s, b.length=%s. Lengths of a and b must be equal.", a.length, b.length));
        }
        int arrayLength = a.length;
        byte[] data = new byte[arrayLength];
        for (int i=0; i < arrayLength; i++) {
            data[i] = (byte) (a[i] ^ b[i]);
        }
        return data;
    }

    /*
     * This function is required to be called to secure a TOTP key for storage
     * in the database.
     * @param key a TOTP key
     * @return a secured TOTP key
     */
    /*
     * This function is used to encrypt a device secret key with the configured
     * app secret for safe storage of the device key in the database.
     * @param key the raw key data
     * @return the encrypted key
     */
    public static byte[] secureKey(byte[] appSecret, byte[] key) {
        if (appSecret == null) {throw new NullPointerException("byte[] uniqueId must not be null.");}
        if (key == null) {throw new NullPointerException("byte[] period must not be null.");}
        if (key.length != appSecret.length) {throw new IllegalArgumentException(String.format("byte[] key is %s bytes. Must be %s bytes (length of byte[] appSecret).", key.length, appSecret.length));}
        return xor(appSecret, key);
    }

    public static byte[] unwrapKey(byte[] appSecret, byte[] key) {
        if (appSecret == null) {throw new NullPointerException("byte[] uniqueId must not be null.");}
        if (key == null) {throw new NullPointerException("byte[] period must not be null.");}
        if (key.length != appSecret.length) {throw new IllegalArgumentException(String.format("byte[] key is %s bytes. Must be %s bytes (length of byte[] appSecret).", key.length, appSecret.length));}
        return xor(appSecret, key);
    }
}
