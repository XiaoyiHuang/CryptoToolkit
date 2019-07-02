package EncryptionToolkit.EllipticCurveCryptography;

import EncryptionToolkit.Utils;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Scanner;

/**
 * A naive implementation of the Elliptic Curve Cryptography algorithm (EllipticCurveCrypto)
 * @author Marco
 *
 * This EllipticCurveCrypto implementation uses {@code secp256k1} domain parameters defined
 * in <i>Standards for Efficient Cryptography (SEC)</i>. For more details
 * regarding this, please refer to: https://en.bitcoin.it/wiki/Secp256k1
 *
 * Reference:
 *  - https://andrea.corbellini.name/2015/05/17/elliptic-curve-cryptography-a-gentle-introduction/
 *  - https://github.com/andreacorbellini/ecc/blob/master/scripts/ecdhe.py
 */

public class EllipticCurveCrypto {

    /** Domain parameter set for Elliptic Curve */
    private static ECCDomain domain;

    /** PRNG for key generation */
    private static final SecureRandom srand = new SecureRandom();

    private static boolean DEBUG_MODE = true;

    private EllipticCurveCrypto(ECCDomain d) {
        domain = d;
    }

    /** Initialize by specifying the domain of the elliptic curve to use */
    public static EllipticCurveCrypto init(ECCDomain d) {
        return new EllipticCurveCrypto(d);
    }

    /**
     * Perform point addition on Elliptic Curve
     * @param _EC_point0
     * @param _EC_point1
     * @return
     */
    public ECPoint pointAdd(ECPoint _EC_point0, ECPoint _EC_point1) {
        ECPoint _sumECPoint = new ECPoint();
        BigInteger m;

        if (!isPointOnCurve(_EC_point0)) {
            return null;
        }

        if (!isPointOnCurve(_EC_point1)) {
            return null;
        }

        if (_EC_point0 == null) {
            return _EC_point1;
        }

        if (_EC_point1 == null) {
            return _EC_point0;
        }

        // Calculate m as (3 * Xp^2 + a)(2 * Yp)^(-1) mod p
        if (_EC_point0.equals(_EC_point1)) {
            m = _EC_point0.x
                    .pow(2)
                    .multiply(BigInteger.valueOf(3))
                    .add(domain.a)
                    .multiply(_EC_point0.y
                            .multiply(BigInteger.TWO)
                            .modInverse(domain.p));
        }
        // Calculate m as (Yp - Yq)*(Xp - Xq)^(-1) mod p
        else {
            BigInteger _xDiff = _EC_point0.x.subtract(_EC_point1.x);
            BigInteger _yDiff = _EC_point0.y.subtract(_EC_point1.y);
            m = _xDiff.modInverse(domain.p).multiply(_yDiff);
        }

        // Calculate Xr as (m^2 - Xp - Xq) mod p
        _sumECPoint.x = m
                .pow(2)
                .subtract(_EC_point0.x)
                .subtract(_EC_point1.x)
                .mod(domain.p);

        // Calculate Yr as -(Yq + m * (Xr - Xq)) mod p
        _sumECPoint.y = _EC_point1.y
                .add(m.multiply(
                        _sumECPoint.x.subtract(_EC_point1.x)))
                .negate()
                .mod(domain.p);

        assert(isPointOnCurve(_sumECPoint));

        return _sumECPoint;
    }

    /**
     * Perform scalar multiplication on Elliptic Curve (n*P)
     * @param multiplier: the member {n} in {n*P}
     * @param multiplicand: the member {P} in {n*P}
     * @return
     */
    public ECPoint scalarMultiply(BigInteger multiplier, ECPoint multiplicand) {
        ECPoint _np = null;
        BigInteger _n = multiplier;
        ECPoint _P = multiplicand;

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
     * Check if a given ECPoint is on the defined elliptic curve
     * @param ECPoint
     * @return
     */
    public boolean isPointOnCurve(ECPoint ECPoint) {
        // If the ECPoint is at infinity
        if (ECPoint == null) {
            return true;
        }
        // Check if (y^2 - x^3 - ax - b) mod p == 0
        return ECPoint.y
                .pow(2)
                .subtract(ECPoint.x.pow(3))
                .subtract(ECPoint.x.multiply(domain.a))
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
        ECPoint serverSharedSecret = scalarMultiply(serverKeyPair.getPrivateKey(), clientKeyPair.getPublicKey());
        ECPoint clientSharedSecret = scalarMultiply(clientKeyPair.getPrivateKey(), serverKeyPair.getPublicKey());

        long endTime = System.currentTimeMillis();

        // Assert that the shared secret generated by the two parties should be the same
        assert serverSharedSecret.equals(clientSharedSecret);

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
        keyPair.setPrivateKey(Utils.getNextRandomBigInteger(srand, "", BigInteger.ONE, domain.n));

        // Generate the correspond public key
        ECPoint publicKey = scalarMultiply(keyPair.getPrivateKey(), new ECPoint(domain.gx, domain.gy));
        keyPair.setPublicKey(publicKey == null ? new ECPoint() : publicKey);

        return keyPair;
    }

    public BigInteger[] doVerifyKeyExchange()
    {
        // Generate a private/public key pair for the server
        KeyPair serverKeyPair = genPrivatePublicKeyPair();
        System.out.println("Server public key pair: " + serverKeyPair.getPublicKey().toString());

        // Wait for user input for client public key info
        Scanner scanner = new Scanner(System.in);
        System.out.print("Please input the client-side public key: ");
        String[] clientPublicKey = scanner.nextLine().split(",");
        String clientPublicKey_x = clientPublicKey[0].trim();
        String clientPublicKey_y = clientPublicKey[1].trim();

        // Parse public key of client
        BigInteger clientPbk_x = new BigInteger(clientPublicKey_x, 16);
        BigInteger clientPbk_y = new BigInteger(clientPublicKey_y, 16);
        ECPoint clientPbk = new ECPoint(clientPbk_x, clientPbk_y);

        // Calculate the correspond shared key
        ECPoint serverSharedSecret = scalarMultiply(serverKeyPair.getPrivateKey(), clientPbk);
        System.out.println("Server-side Shared key: " + serverSharedSecret.toString());

        // Obtain the shared key calculated in client side
        System.out.print("Please input the shared secret calculated in client side: ");
        String[] clientSharedSecret = scanner.nextLine().split(",");
        String clientSharedSecret_x = clientSharedSecret[0].trim();
        String clientSharedSecret_y = clientSharedSecret[1].trim();

        BigInteger clientShr_x = new BigInteger(clientSharedSecret_x, 16);
        BigInteger clientShr_y = new BigInteger(clientSharedSecret_y, 16);
        ECPoint _clientSharedSecret = new ECPoint(clientShr_x, clientShr_y);

        // Validate the shared key
        System.out.println("Is shared key matched: " + _clientSharedSecret.equals(serverSharedSecret));

        return new BigInteger[]{serverSharedSecret.x, serverSharedSecret.y};
    }

    public static void main(String[] args) {
        ECCDomain domain = ECCDomain_secp256k1.getInstance();
        EllipticCurveCrypto ecc = EllipticCurveCrypto.init(domain);
        ecc.doVerifyKeyExchange();
    }
}

