package EncryptionToolkit;

import EncryptionToolkit.AES.AES;
import EncryptionToolkit.EllipticCurveCryptography.ECCDomain;
import EncryptionToolkit.EllipticCurveCryptography.ECCDomain_secp256k1;
import EncryptionToolkit.EllipticCurveCryptography.EllipticCurveCrypto;

import java.math.BigInteger;
import java.util.Scanner;

/**
 * SecureDataTransmission
 *
 * @author: Marco
 * Date: 2019/7/1 17:29
 */
public class SecureDataTransmission {
    private static EllipticCurveCrypto eccMod;
    private static AES aesMod;
    private static boolean hasInitAES = false;

    private static BigInteger[] DoKeyExchange()
    {
        ECCDomain domain = ECCDomain_secp256k1.getInstance();
        eccMod = EllipticCurveCrypto.init(domain);
        return eccMod.doVerifyKeyExchange();
    }

    private static void InitAES(BigInteger key, BigInteger IV)
    {
        aesMod = AES.initWithAESParams(key.toString(), IV.toString());
        hasInitAES = true;
    }

    private static String EncryptData(String plainText)
    {
        if (!hasInitAES)
        {
            return "";
        }
        return aesMod.encrypt(plainText);
    }

    private static String DecryptData(String cipherText)
    {
        if (!hasInitAES)
        {
            return "";
        }
        return aesMod.decrypt(cipherText);
    }

    public static void main(String[] args)
    {
        BigInteger[] sharedSecret = DoKeyExchange();

        InitAES(sharedSecret[0], sharedSecret[1]);

//        String plainText = "It's rainy today. Please be aware!";
//        System.out.println("Plain text: " + plainText);
//
//        String cipher = EncryptData(plainText);
//        System.out.println("Cipher text: " + cipher);
//
//        String recoveredText = DecryptData(cipher);
//        System.out.println("Recovered plain text: " + recoveredText);

        Scanner scanner = new Scanner(System.in);
        System.out.print("Please input the cipher text from the client: ");
        String cipherText = scanner.nextLine();

        String recoveredText = DecryptData(cipherText);
        System.out.println("Recovered plain text: " + recoveredText);
    }
}
