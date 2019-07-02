package EncryptionToolkit.EllipticCurveCryptography;

import java.math.BigInteger;

/**
 * ECCDomain_secp256k1
 * @author Marco
 */
public class ECCDomain_secp256k1 extends ECCDomain {
    private static ECCDomain_secp256k1 instance = new ECCDomain_secp256k1();

    private ECCDomain_secp256k1() {
        p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
        a = BigInteger.ZERO;
        b = new BigInteger("7");
        gx = new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
        gy = new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
        n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
        h = new BigInteger("1");
    }

    public static ECCDomain_secp256k1 getInstance() {
        return instance;
    }
}
