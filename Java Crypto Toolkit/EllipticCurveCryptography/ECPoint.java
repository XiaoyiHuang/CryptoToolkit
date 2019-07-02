package EncryptionToolkit.EllipticCurveCryptography;

import EncryptionToolkit.Utils;

import java.math.BigInteger;

/**
 * ECPoint
 * @author Marco
 */
public class ECPoint {
    public BigInteger x;
    public BigInteger y;

    public ECPoint(BigInteger x, BigInteger y) {
        this.x = x;
        this.y = y;
    }

    public ECPoint() {
        this.x = BigInteger.ZERO;
        this.y = BigInteger.ZERO;
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof ECPoint)) {
            return false;
        }

        ECPoint _p = (ECPoint)obj;
        return this.x.equals(_p.x) && this.y.equals(_p.y);
    }

    @Override
    public String toString() {
        return Utils.bytesToHex(this.x.toByteArray()) + ", " + Utils.bytesToHex(this.y.toByteArray());
    }
}
