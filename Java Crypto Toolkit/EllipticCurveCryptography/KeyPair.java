package EncryptionToolkit.EllipticCurveCryptography;

import java.math.BigInteger;

/**
 * KeyPair
 * @author Marco
 */
public class KeyPair {
    BigInteger privateKey;
    private ECPoint publicKey;

    public KeyPair() {}

    public KeyPair(BigInteger privateKey, ECPoint publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    void setPrivateKey(BigInteger privateKey) {
        this.privateKey = privateKey;
    }

    public void setPublicKey(ECPoint publicKey) {
        this.publicKey = publicKey;
    }

    BigInteger getPrivateKey() {
        return privateKey;
    }

    public ECPoint getPublicKey() {
        return publicKey;
    }
}
