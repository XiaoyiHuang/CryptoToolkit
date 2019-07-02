using System;
using System.Numerics;

namespace AES
{
    class SecureDataTransmission
    {
        private static EllipticCurveCrypto eccMod;
        private static AES aesMod;

        private static BigInteger[] DoKeyExchange()
        {
            ECCDomain domain = ECCDomain_secp256k1.getInstance();
            eccMod = EllipticCurveCrypto.init(domain, false);
            return eccMod.DoVerifyKeyExchange();
        }

        private static void InitAES(BigInteger key, BigInteger IV)
        {
            aesMod = AES.init(key, IV);
        }

        private static string EncryptData(string plainText)
        {
            return aesMod.Encrypt(plainText);
        }

        private static string DecryptData(string cipherText)
        {
            return aesMod.Decrypt(cipherText);
        }

        private static void Main()
        {
            BigInteger[] sharedSecret = DoKeyExchange();

            InitAES(sharedSecret[0], sharedSecret[1]);

            string plainText = "It's rainy today. Please be aware!";
            Console.WriteLine("Plain text: {0}", plainText);

            string cipherText = EncryptData(plainText);
            Console.WriteLine("Cipher text in base64: {0}", cipherText);

            //Console.Write("Please input the cipher text in Base64 format: ");
            //string cipherText = Console.ReadLine();

            string recoveredText = DecryptData(cipherText);
            Console.WriteLine("Recovered plain text: {0}", recoveredText);

            Console.ReadLine();
        }
    }
}
