using System.Numerics;

namespace AES
{
    /**
     * EllipticCurveCrypto Domain Parameter Set
     * @author Marco
     *
     * Specify Elliptic Curve Domain Parameters: Domain parameters for EllipticCurveCrypto
     * are defined as a sextuple (p, a, b, G, n, h), where:
     *   The prime {@code p} defines the size of the finite field
     *   The coefficients {@code a} and {@code b} define the elliptic curve equation
     *   The base point {@code G} is defined to generate our subgroup, whose {x} and {y} coordinates 
     *   are denoted as {gx} and {gy}
     *   The order of the subgroup is defined as {@code n}
     *   The co-factor of the subgroup is defined as {@code h}
     */
    public abstract class ECCDomain
    {
        /** Size of the finite field */
        public BigInteger p;

        /** The {a} parameter of the elliptic curve */
        public BigInteger a;

        /** The {b} parameter of the elliptic curve */
        public BigInteger b;

        /** The x coordinate of the base point G */
        public BigInteger gx;

        /** The y coordinate of the base point G */
        public BigInteger gy;

        /** The order of the subgroup */
        public BigInteger n;

        /** The co-factor of the subgroup */
        public BigInteger h;
    }
}
