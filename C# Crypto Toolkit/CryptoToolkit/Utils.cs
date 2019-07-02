using System;
using System.Numerics;
using System.Security.Cryptography;

namespace AES
{
    class Utils
    {
        /** Lookup table for converting to Hexadecimal characters */
        private static char[] hexArray = "0123456789ABCDEF".ToCharArray();

        /**
         * Convert a little-endian byte array to a big-endian hex String
         * @param bytes
         * @return
         */
        public static String BytesToHex(byte[] bytes)
        {
            int len = bytes.Length;

            // Skip the zero byte appended at the end of the byte array if exists
            if (bytes[len - 1] == 0)
            {
                len = bytes.Length - 1;
            }

            char[] hexChars = new char[len * 2];

            for (int i = len - 1; i >= 0; i--)
            {
                int v = bytes[i] & 0xFF;
                hexChars[(len - i - 1) * 2] = hexArray[v >> 4];
                hexChars[(len - i - 1) * 2 + 1] = hexArray[v & 0x0F];
            }
            return new String(hexChars);
        }

        /**
         * Convert a big-endian hex string to a little-endian byte array
         * @param hex
         * @return
         */
        public static byte[] HexStrToBytes(String hex, bool appendZero = true)
        {
            // Check if the highest-order bit is set
            bool isHexLengthOdd = (hex.Length & 0x1) == 0x1;
            bool isHighestBitSet = !isHexLengthOdd && ((Convert.ToByte(hex.Substring(0, 2), 16) & 0x80) >> 7) == 1;

            byte[] bytes = new byte[((hex.Length + 1) >> 1) + (appendZero && isHighestBitSet ? 1 : 0)];
            int byteIdx = 0;
            for (int i = hex.Length - 1; i >= 0; i -= 2)
            {
                if (i < 1)
                {
                    bytes[byteIdx++] = Byte.Parse(hex.Substring(i, 1), System.Globalization.NumberStyles.HexNumber);
                }
                else
                {
                    bytes[byteIdx++] = Byte.Parse(hex.Substring(i - 1, 2), System.Globalization.NumberStyles.HexNumber);
                }
            }

            // Append Zero to the end to pass the array as an unsigned integer
            if (appendZero && isHighestBitSet)
            {
                bytes[bytes.Length - 1] = 0;
            }

            return bytes;
        }

        /**
         * Generate next random number within given range
         * @param rngCsp: Instance of RNG (Random Number Generation) service provider
         * @param lowerLimit: Lower limit of the target random number (exclusive)
         * @param upperLimit: Upper limit of the target random number (exclusive)
         * @return
         */
        public static BigInteger GetNextRandomBigInteger(RNGCryptoServiceProvider rngCsp, BigInteger lowerLimit, BigInteger upperLimit)
        {
            byte[] randomByte = new byte[upperLimit.ToByteArray().Length];
            BigInteger nextRandom;

            // Generate next random sequence within given range
            do
            {
                rngCsp.GetBytes(randomByte);
                nextRandom = new BigInteger(randomByte);
            } while (BigInteger.Compare(nextRandom, upperLimit) >= 0 || BigInteger.Compare(nextRandom, lowerLimit) <= 0);

            return nextRandom;
        }

        /**
         * Generate next random number of given length
         * @param rngCsp: Instance of RNG (Random Number Generation) service provider
         * @param byteLen: Byte length of the target random number
         * @return
         */
        public static BigInteger GetNextRandomBigIntegerOfLength(RNGCryptoServiceProvider rngCsp, int byteLen)
        {
            byte[] randomByte = new byte[byteLen];
            rngCsp.GetBytes(randomByte);
            BigInteger nextRandom = new BigInteger(randomByte);
            return nextRandom;
        }

        /**
         * Provide negative-value-friendly calculating of mod inverse, which always derives positive
         * results despite the sign of the provided value
         */
        public static BigInteger ModInverse(BigInteger value, BigInteger modulus)
        {
            //bool isValueNegative = false;

            if (value.CompareTo(BigInteger.Zero) < 0)
            {
                value = BigInteger.Add(value, modulus);
            }

            return BigInteger.ModPow(value, BigInteger.Subtract(modulus, new BigInteger(2)), modulus);
        }

        /**
         * Wrapper of the ModPow method in the BigInteger class, prevent deriving negative result 
         * when negative value is provided
         */
        public static BigInteger ModPow(BigInteger value, BigInteger exponent, BigInteger modulus)
        {
            if (value.CompareTo(BigInteger.Zero) < 0)
            {
                return BigInteger.Add(BigInteger.ModPow(value, exponent, modulus), modulus);
            }
            else
            {
                return BigInteger.ModPow(value, exponent, modulus);
            }
        }

        /**
         * Clamp supplied byte array to contain only 128 elements
         */
        public static byte[] ClampKeySize(byte[] key)
        {
            int originalSize = key.Length;

            // Only accepts the leading 16 bytes for now (as the server side only accepts 128-bit AES)
            if (originalSize == 16)
            {
                return key;
            }

            byte[] resizedArray;

            if (originalSize > 16)
            {
                resizedArray = new byte[16];
                Array.Copy(key, resizedArray, 16);
                return resizedArray;
            }
            else
            {
                return key;
            }
        }
    }
}
