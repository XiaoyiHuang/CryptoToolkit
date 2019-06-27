package EncryptionUtils.EllipticCurveCryptography;

import java.math.BigInteger;

/**
 * Point
 * @author Marco
 */
public class Point {
    public BigInteger x;
    public BigInteger y;

    public Point(BigInteger x, BigInteger y) {
        this.x = x;
        this.y = y;
    }

    public Point() {
        this.x = BigInteger.ZERO;
        this.y = BigInteger.ZERO;
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof Point)) {
            return false;
        }

        Point _p = (Point)obj;
        return this.x.equals(_p.x) && this.y.equals(_p.y);
    }

    @Override
    public String toString() {
        return Utils.bytesToHex(this.x.toByteArray()) + ", " + Utils.bytesToHex(this.y.toByteArray());
    }
}
