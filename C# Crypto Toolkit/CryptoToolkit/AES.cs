using System;
using System.IO;
using System.Security.Cryptography;
using System.Numerics;
using System.Text;


namespace AES
{
    class AES
    {
        // Symmetric key for AES en-/decryption
        private byte[] Key = new byte[16];

        // Initialization vector for AES
        private byte[] IV = new byte[16];

        private AES(BigInteger key, BigInteger iv)
        {
            this.Key = Utils.ClampKeySize(Encoding.UTF8.GetBytes(key.ToString()));
            this.IV = Utils.ClampKeySize(Encoding.UTF8.GetBytes(iv.ToString()));

            //Array.Copy(keyBytes, this.Key, Math.Min(keyBytes.Length, this.Key.Length));
            //Array.Copy(ivBytes, this.IV, Math.Min(ivBytes.Length, this.IV.Length));
        }

        public static AES init(BigInteger key, BigInteger iv)
        {
            return new AES(key, iv);
        }

        private RijndaelManaged GetEncryptDecryptHandler()
        {
            RijndaelManaged aes = new RijndaelManaged();
            aes.Key = Key;
            aes.IV = IV;
            aes.Padding = PaddingMode.PKCS7;
            aes.BlockSize = 128;
            aes.KeySize = 128;
            aes.Mode = CipherMode.CBC;
            aes.Key = this.Key;
            aes.IV = this.IV;

            return aes;
        }

        public string Encrypt(string plainText)
        {
            // Transform the plain text to proper byte array
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);

            // Perform encryption
            byte[] cipherBytes = GetEncryptDecryptHandler().CreateEncryptor().TransformFinalBlock(plainBytes, 0, plainBytes.Length);

            return Convert.ToBase64String(cipherBytes);
        }

        public string Decrypt(string cipher)
        {
            // Transform the cipher text to proper byte array
            byte[] cipherBytes = Convert.FromBase64String(cipher);

            // Perform decryption
            byte[] plainBytes = GetEncryptDecryptHandler().CreateDecryptor().TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);

            return Encoding.UTF8.GetString(plainBytes);
        }
    }
}