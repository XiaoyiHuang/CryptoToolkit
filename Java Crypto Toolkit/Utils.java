package EncryptionToolkit;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Utils
 * @author Marco
 */
public class Utils {
    /** Lookup table for converting to Hexadecimal characters */
    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

    /**
     * Converting a byte array to a hex String
     * @param bytes
     * @return
     */
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hexChars[i * 2] = hexArray[v >>> 4];
            hexChars[i * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * Generate next random number within given range
     * @param srand
     * @param seed: Seed for initializing PRNG
     * @param lowerLimit
     * @param upperLimit
     * @return
     */
    public static BigInteger getNextRandomBigInteger(SecureRandom srand, String seed, BigInteger lowerLimit, BigInteger upperLimit) {
        // Re-Seed the PRNG if necessary
        if (seed != null && seed.length() > 0) {
            srand.setSeed(seed.getBytes());
        }

        // Generate next random sequence within given range
        BigInteger random;
        do {
            random = new BigInteger(upperLimit.bitLength(), srand);
        } while (random.compareTo(upperLimit) >= 0 || random.compareTo(lowerLimit) <= 0 || random.bitLength() < upperLimit.bitLength());

        return random;
    }

    /**
     * Generate next random number of given length
     * @param seed: Seed for initializing PRNG
     * @return
     */
    public static BigInteger getNextRandomBigIntegerOfLength(SecureRandom srand, String seed, int bitLen) {
        // Re-Seed the PRNG if necessary
        if (seed != null && seed.length() > 0) {
            srand.setSeed(seed.getBytes());
        }

        // Generate next random sequence of {bitLen} size
        BigInteger random;
        do {
            random = new BigInteger(bitLen, srand);
        } while (random.bitLength() != bitLen);

        return random;
    }

    /**
     * Convert a BigInteger to a byte array without the leading sign byte
     * @param sequence
     * @return
     */
    public static byte[] toUnsignedByteArray(BigInteger sequence) {
        byte[] bytes = sequence.toByteArray();
        return Arrays.copyOfRange(bytes, 1, bytes.length);
    }

    /**
     * Clamp supplied byte array to contain only 128 elements
     */
    public static byte[] clampKeySize(byte[] key)
    {
        int originalSize = key.length;

        // Only accepts the leading 16 bytes for now (as the server side only accepts 128-bit AES)
        if (originalSize == 16)
        {
            return key;
        }

        if (originalSize > 16)
        {
            return Arrays.copyOf(key, 16);
        }
        else
        {
            return key;
        }
    }

    /**
     * Convert an unsigned little-endian byte array to a signed big-endian byte array
     * @param bytes: Unsigned little-endian byte array
     * @return
     */
    public static byte[] ToBigEndianBytes(byte[] bytes) {
        int len = bytes.length;
        int index = len - 1;
        byte[] convertedBytes = new byte[len];

        for (int i = 0; i < len; i++) {
            convertedBytes[index--] = (byte)bytes[i];
        }
        return convertedBytes;
    }
}
