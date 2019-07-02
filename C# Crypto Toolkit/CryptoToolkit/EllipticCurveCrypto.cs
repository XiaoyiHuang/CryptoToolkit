using System;
using System.Numerics;
using System.Security.Cryptography;

namespace AES
{
    class EllipticCurveCrypto
    {
        /** Domain parameter set for Elliptic Curve */
        private static ECCDomain domain;

        /** PRNG for key generation */
        private static RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();

        private static bool DEBUG_MODE;

        private EllipticCurveCrypto(ECCDomain d, bool debugMode)
        {
            domain = d;
            DEBUG_MODE = debugMode;
        }

        /** Initialize by specifying the domain of the elliptic curve to use */
        public static EllipticCurveCrypto init(ECCDomain d, bool debugMode = true)
        {
            return new EllipticCurveCrypto(d, debugMode);
        }

        /**
         * Perform point addition on Elliptic Curve
         * @param _EC_point0
         * @param _EC_point1
         * @return
         */
        public ECPoint PointAdd(ECPoint _EC_point0, ECPoint _EC_point1)
        {
            ECPoint _sumECPoint = new ECPoint();
            BigInteger m;

            if (DEBUG_MODE && !IsPointOnCurve(_EC_point0))
            {
                return null;
            }

            if (DEBUG_MODE && !IsPointOnCurve(_EC_point1))
            {
                return null;
            }

            if (_EC_point0 == null)
            {
                return _EC_point1;
            }

            if (_EC_point1 == null)
            {
                return _EC_point0;
            }

            // Calculate m as (3 * Xp^2 + a)(2 * Yp)^(-1) mod p
            if (_EC_point0.Equals(_EC_point1))
            {
                m = BigInteger.Multiply(
                            BigInteger.Add(
                                BigInteger.Multiply(
                                    BigInteger.Pow(_EC_point0.x, 2), new BigInteger(3))
                            , domain.a),
                            Utils.ModInverse(
                                BigInteger.Multiply(new BigInteger(2), _EC_point0.y),
                            domain.p)
                    );
            }
            // Calculate m as (Yp - Yq)*(Xp - Xq)^(-1) mod p
            else
            {

                BigInteger _xDiff = BigInteger.Subtract(_EC_point0.x, _EC_point1.x);
                BigInteger _yDiff = BigInteger.Subtract(_EC_point0.y, _EC_point1.y);
                BigInteger mi = Utils.ModInverse(_xDiff, domain.p);
                m = BigInteger.Multiply(_yDiff, mi);
            }

            // Calculate Xr as (m^2 - Xp - Xq) mod p
            _sumECPoint.x = Utils.ModPow(
                                BigInteger.Subtract(
                                    BigInteger.Pow(m, 2), BigInteger.Add(_EC_point0.x, _EC_point1.x)
                                )
                            , 1, domain.p);

            // Calculate Yr as -(Yq + m * (Xr - Xq)) mod p
            _sumECPoint.y = Utils.ModPow(
                                BigInteger.Negate(
                                    BigInteger.Add(_EC_point1.y,
                                        BigInteger.Multiply(m,
                                            BigInteger.Subtract(_sumECPoint.x, _EC_point1.x)
                                        )
                                    )),
                            1, domain.p);

            if (DEBUG_MODE && !IsPointOnCurve(_sumECPoint))
            {
                throw new Exception("RESULT OF ADD POINT OPERATION SHOULD BE ON THE CURVE");
            }

            return _sumECPoint;
        }

        /**
         * Perform scalar multiplication on Elliptic Curve (n*P)
         * @param multiplier: the member {n} in {n*P}
         * @param multiplicand: the member {P} in {n*P}
         * @return
         */
        public ECPoint ScalarMultiply(BigInteger multiplier, ECPoint multiplicand)
        {
            ECPoint _np = null;
            BigInteger _n = multiplier;
            ECPoint _P = multiplicand;

            while (_n.CompareTo(0) > 0)
            {
                // Check if point addition is needed for current bit index
                if (!_n.IsEven)
                {
                    _np = PointAdd(_np, _P);
                }

                _n = BigInteger.Divide(_n, new BigInteger(2));
                _P = PointAdd(_P, _P);
            }

            return _np;
        }

        /**
         * Check if a given ECPoint is on the defined elliptic curve
         * @param ECPoint
         * @return
         */
        public bool IsPointOnCurve(ECPoint ECPoint)
        {
            // If the ECPoint is at infinity
            if (ECPoint == null)
            {
                return true;
            }
            // Check if (y^2 - x^3 - ax - b) mod p == 0
            return BigInteger.ModPow(
                      BigInteger.Subtract(
                          BigInteger.Subtract(BigInteger.Pow(ECPoint.y, 2), 
                              BigInteger.Pow(ECPoint.x, 3)
                          ), 
                          BigInteger.Add(BigInteger.Multiply(domain.a, ECPoint.x), domain.b)
                      )
                   , 1, domain.p)
                   .Equals(BigInteger.Zero);
        }

        /**
         * Simulate a complete round of Elliptic Curve Diffie-Hellman(ECDH) Key Exchange
         * @return
         */
        public KeyPair[] DoECDHKeyExchange()
        {
            // Generate private/public key pair for server
            KeyPair serverKeyPair = GenPrivatePublicKeyPair();

            // Generate private/public key pair for client
            KeyPair clientKeyPair = GenPrivatePublicKeyPair();

            // Client & Server exchange their public keys and calculate the shared secret
            ECPoint serverSharedSecret = ScalarMultiply(serverKeyPair.GetPrivateKey(), clientKeyPair.GetPublicKey());
            ECPoint clientSharedSecret = ScalarMultiply(clientKeyPair.GetPrivateKey(), serverKeyPair.GetPublicKey());

            // Assert that the shared secret generated by the two parties should be the same
            if (!serverSharedSecret.Equals(clientSharedSecret))
            {
                if (DEBUG_MODE)
                {
                    throw new Exception("UNMATCHED CALCULATION OF SHARED SECRET FROM CLIENT AND SERVER");
                }
                else
                {
                    // Instead of throwing an exception, do the whole process all over again
                    return DoECDHKeyExchange();
                }
            }

            if (DEBUG_MODE)
            {
                Console.WriteLine("Server private key: " + Utils.BytesToHex(serverKeyPair.GetPrivateKey().ToByteArray()));
                Console.WriteLine("Client private key: " + Utils.BytesToHex(clientKeyPair.GetPrivateKey().ToByteArray()));
                Console.WriteLine("================================================================================");
                Console.WriteLine("Server public key: " + serverKeyPair.GetPublicKey().ToString());
                Console.WriteLine("Client public key: " + clientKeyPair.GetPublicKey().ToString());
                Console.WriteLine("================================================================================");
                Console.WriteLine("Server Shared key: " + serverSharedSecret.ToString());
                Console.WriteLine("Client Shared key: " + clientSharedSecret.ToString());
            }

            return new KeyPair[] { serverKeyPair, clientKeyPair };
        }

        public BigInteger[] DoVerifyKeyExchange()
        {
            Console.Write("Please input X factor of server-side public key: ");
            string serverPublicKey_x = Console.ReadLine();
            Console.Write("Please input Y factor of server-side public key: ");
            string serverPublicKey_y = Console.ReadLine();

            // Parse public key of server
            BigInteger serverPbk_x = new BigInteger(Utils.HexStrToBytes(serverPublicKey_x));
            BigInteger serverPbk_y = new BigInteger(Utils.HexStrToBytes(serverPublicKey_y));
            ECPoint serverPbk = new ECPoint(serverPbk_x, serverPbk_y);

            // Generate a private/public key pair for the client
            KeyPair clientKeyPair = GenPrivatePublicKeyPair();

            // Calculate the correspond shared key
            ECPoint clientSharedSecret = ScalarMultiply(clientKeyPair.GetPrivateKey(), serverPbk);

            Console.WriteLine("Client public key pair: {0}", clientKeyPair.GetPublicKey().ToString());
            Console.WriteLine("Shared key: {0}", clientSharedSecret.ToString());

            // Returns the x-factor of the shared secret as the symmetric key
            return new BigInteger[] { clientSharedSecret.x, clientSharedSecret.y };
        }

        public KeyPair GenPrivatePublicKeyPair()
        {
            KeyPair keyPair = new KeyPair();

            // Generate a random private key
            keyPair.SetPrivateKey(Utils.GetNextRandomBigInteger(rngCsp, BigInteger.One, domain.n));

            // Generate the correspond public key
            ECPoint publicKey = ScalarMultiply(keyPair.GetPrivateKey(), new ECPoint(domain.gx, domain.gy));
            keyPair.SetPublicKey(publicKey == null ? new ECPoint() : publicKey);

            return keyPair;
        }

        //public static void Main()
        //{
        //    ECCDomain domain = ECCDomain_secp256k1.getInstance();
        //    EllipticCurveCrypto ecc = EllipticCurveCrypto.init(domain, true);
        //    int trialRounds = 50;

        //    // Stopwatch for calculation performance benchmark
        //    var watch = System.Diagnostics.Stopwatch.StartNew();

        //    ecc.DoVerifyKeyExchange();

        //    // Stop the watch
        //    watch.Stop();

        //    Console.WriteLine("================================================================================");
        //    Console.WriteLine("Average time: " + watch.ElapsedMilliseconds / trialRounds + " ms");

        //    Console.ReadLine();
        //}
    }
}
