package EncryptionUtils.EllipticCurveCryptography;

import java.math.BigInteger;

/**
 * KeyPair
 * @author Marco
 */
public class KeyPair {
    BigInteger privateKey;
    private Point publicKey;

    public KeyPair() {}

    public KeyPair(BigInteger privateKey, Point publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    void setPrivateKey(BigInteger privateKey) {
        this.privateKey = privateKey;
    }

    public void setPublicKey(Point publicKey) {
        this.publicKey = publicKey;
    }

    BigInteger getPrivateKey() {
        return privateKey;
    }

    public Point getPublicKey() {
        return publicKey;
    }
}
