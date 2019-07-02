using System;
using System.Numerics;

namespace AES
{
    /**
     * ECCDomain_secp256k1
     * @author Marco
     */
    public class ECCDomain_secp256k1: ECCDomain
    {
        private static ECCDomain_secp256k1 instance = new ECCDomain_secp256k1();

        private ECCDomain_secp256k1()
        {
            p = new BigInteger(Utils.HexStrToBytes("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"));
            a = BigInteger.Zero;
            b = new BigInteger(7);
            gx = new BigInteger(Utils.HexStrToBytes("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"));
            gy = new BigInteger(Utils.HexStrToBytes("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"));
            n = new BigInteger(Utils.HexStrToBytes("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"));
            h = BigInteger.One;
        }

        public static ECCDomain_secp256k1 getInstance()
        {
            return instance;
        }
    }
}
