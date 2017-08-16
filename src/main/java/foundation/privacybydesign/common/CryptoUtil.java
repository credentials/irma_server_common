package foundation.privacybydesign.common;

/**
 * Class with methods not belonging anywhere else.
 */
public class CryptoUtil {
    /**
     * Compare two byte arrays in constant time. I haven't been able to
     * quickly find a Java API for this (which would be a much better idea
     * than reinventing the wheel).
     */
    public static boolean isEqualsConstantTime(char[] a, char[] b) {
        // I hope this is safe...
        // https://codahale.com/a-lesson-in-timing-attacks/
        // https://golang.org/src/crypto/subtle/constant_time.go (ConstantTimeCompare)
        // In Go, they also take special care to compare the result byte
        // bit-for-bit in constant time.

        if (a.length != b.length) {
            return false;
        }

        byte result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }
}
