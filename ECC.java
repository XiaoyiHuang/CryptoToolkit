package EncryptionUtils.EllipticCurveCryptography;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * A naive implementation of the Elliptic Curve Cryptography algorithm (ECC)
 * @author Marco
 *
 * This ECC implementation uses {@code secp256k1} domain parameters defined
 * in <i>Standards for Efficient Cryptography (SEC)</i>. For more details
 * regarding this, please refer to: https://en.bitcoin.it/wiki/Secp256k1
 *
 * Reference:
 *  - https://andrea.corbellini.name/2015/05/17/elliptic-curve-cryptography-a-gentle-introduction/
 *  - https://github.com/andreacorbellini/ecc/blob/master/scripts/ecdhe.py
 */

public class ECC {

    /** Domain parameter set for Elliptic Curve */
    private static ECCDomain domain;

    /** PRNG for key generation */
    private static final SecureRandom srand = new SecureRandom();

    private static boolean DEBUG_MODE = true;

    private ECC(ECCDomain d) {
        domain = d;
    }

    /** Initialize by specifying the domain of the elliptic curve to use */
    public static ECC init(ECCDomain d) {
        return new ECC(d);
    }

    /**
     * Generate next random number of given length
     * @param seed: Seed for initializing PRNG
     * @return
     */
    public BigInteger getNextRandomBigInteger(String seed, BigInteger lowerLimit, BigInteger upperLimit) {
        // Re-Seed the PRNG if necessary
        if (seed != null && seed.length() > 0) {
            srand.setSeed(seed.getBytes());
        }

        // Generate next random sequence of {byteLen} size
        BigInteger random;
        do {
            random = new BigInteger(upperLimit.bitLength(), srand);
        } while (random.compareTo(upperLimit) >= 0 || random.compareTo(lowerLimit) <= 0);

        return random;
    }

    /**
     * Perform point addition on Elliptic Curve
     * @param _point0
     * @param _point1
     * @return
     */
    public Point pointAdd(Point _point0, Point _point1) {
        Point _sumPoint = new Point();
        BigInteger m;

        if (!isPointOnCurve(_point0)) {
            return null;
        }

        if (!isPointOnCurve(_point1)) {
            return null;
        }

        if (_point0 == null) {
            return _point1;
        }

        if (_point1 == null) {
            return _point0;
        }

        // Calculate m as (3*Xp^2 + a)(2*Yp)^(-1) mod p
        if (_point0.equals(_point1)) {
            m = _point0.x
                    .pow(2)
                    .multiply(BigInteger.valueOf(3))
                    .add(domain.a)
                    .multiply(_point0.y
                            .multiply(BigInteger.TWO)
                            .modInverse(domain.p));
        }
        // Calculate m as (Yp - Yq)*(Xp - Xq)^(-1) mod p
        else {
            BigInteger _xDiff = _point0.x.subtract(_point1.x);
            BigInteger _yDiff = _point0.y.subtract(_point1.y);
            m = _xDiff.modInverse(domain.p).multiply(_yDiff);
        }

        _sumPoint.x = m
                .pow(2)
                .subtract(_point0.x)
                .subtract(_point1.x)
                .mod(domain.p);

        _sumPoint.y = _point1.y
                .add(m.multiply(
                        _sumPoint.x.subtract(_point1.x)))
                .negate()
                .mod(domain.p);

        assert(isPointOnCurve(_sumPoint));

        return _sumPoint;
    }

    /**
     * Perform scalar multiplication on Elliptic Curve (n*P)
     * @param multiplier: the member {n} in {n*P}
     * @param multiplicand: the member {P} in {n*P}
     * @return
     */
    public Point scalarMultiply(BigInteger multiplier, Point multiplicand) {
        Point _np = null;
        BigInteger _n = multiplier;
        Point _P = multiplicand;

        while (_n.compareTo(BigInteger.ZERO) > 0) {
            // Check if point addition is needed for current bit index
            if (_n.testBit(0)) {
                _np = pointAdd(_np, _P);
            }

            _n = _n.divide(BigInteger.TWO);
            _P = pointAdd(_P, _P);
        }

        return _np;
    }

    /**
     * Check if a given point is on the defined elliptic curve
     * @param point
     * @return
     */
    public boolean isPointOnCurve(Point point) {
        // If the point is at infinity
        if (point == null) {
            return true;
        }
        // Check if (y^2 - x^3 - ax - b) mod p == 0
        return point.y
                .pow(2)
                .subtract(point.x.pow(3))
                .subtract(point.x.multiply(domain.a))
                .subtract(domain.b)
                .mod(domain.p)
                .equals(BigInteger.ZERO);
    }

    /**
     * Simulate a complete round of Elliptic Curve Diffie-Hellman(ECDH) Key Exchange
     * @return
     */
    public KeyPair[] doECDHKeyExchange() {
        long startTime = System.currentTimeMillis();

        // Generate private/public key pair for server
        KeyPair serverKeyPair = genPrivatePublicKeyPair();

        // Generate private/public key pair for client
        KeyPair clientKeyPair = genPrivatePublicKeyPair();

        // Client & Server exchange their public keys and calculate the shared secret
        Point serverSharedSecret = scalarMultiply(serverKeyPair.getPrivateKey(), clientKeyPair.getPublicKey());
        Point clientSharedSecret = scalarMultiply(clientKeyPair.getPrivateKey(), serverKeyPair.getPublicKey());

        long endTime = System.currentTimeMillis();

        // Assert that the shared secret generated by the two parties should be the same
        assert serverSharedSecret.equals(clientSharedSecret);

        if (!serverSharedSecret.equals(clientSharedSecret)) {
            throw new IllegalStateException("UNMATCHED SHARED SECRET");
        }

        if (DEBUG_MODE) {
            System.out.println("Server private key: " + Utils.bytesToHex(serverKeyPair.getPrivateKey().toByteArray()));
            System.out.println("Client private key: " + Utils.bytesToHex(clientKeyPair.getPrivateKey().toByteArray()));
            System.out.println("================================================================================");
            System.out.println("Server public key: " + serverKeyPair.getPublicKey());
            System.out.println("Client public key: " + clientKeyPair.getPublicKey());
            System.out.println("================================================================================");
            System.out.println("Shared key: " + serverSharedSecret.toString());
            System.out.println("================================================================================");
            System.out.println("Elapsed time: " + (endTime - startTime) + " ms");
        }

        return new KeyPair[]{serverKeyPair, clientKeyPair};
    }

    public KeyPair genPrivatePublicKeyPair() {
        KeyPair keyPair = new KeyPair();

        // Generate a random private key
        keyPair.setPrivateKey(getNextRandomBigInteger("", BigInteger.ONE, domain.n));

        // Generate the correspond public key
        Point publicKey = scalarMultiply(keyPair.getPrivateKey(), new Point(domain.gx, domain.gy));
        keyPair.setPublicKey(publicKey == null ? new Point() : publicKey);

        return keyPair;
    }

    public static void main(String[] args) {
        ECCDomain domain = ECCDomain_secp256k1.getInstance();
        ECC ecc = ECC.init(domain);

        for (int i = 0; i < 100; i++) {
            ecc.doECDHKeyExchange();
        }
    }
}

