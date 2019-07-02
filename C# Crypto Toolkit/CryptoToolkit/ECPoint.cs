using System;
using System.Numerics;

namespace AES
{
    /**
     * ECPoint
     * @author Marco
     */
    public class ECPoint
    {
        public BigInteger x;
        public BigInteger y;

        public ECPoint(BigInteger x, BigInteger y)
        {
            this.x = x;
            this.y = y;
        }

        public ECPoint()
        {
            this.x = new BigInteger(0);
            this.y = new BigInteger(0);
        }

        public override bool Equals(Object obj)
        {
            if (!(obj is ECPoint)) {
                return false;
            }

            ECPoint _p = (ECPoint)obj;
            return this.x.Equals(_p.x) && this.y.Equals(_p.y);
        }

        public override string ToString()
        {
            return Utils.BytesToHex(this.x.ToByteArray()) + ", " + Utils.BytesToHex(this.y.ToByteArray());
        }
    }
}
