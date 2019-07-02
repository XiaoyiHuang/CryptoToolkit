using System.Numerics;

namespace AES
{
    /**
     * KeyPair
     * @author Marco
     */
    public class KeyPair
    {
        BigInteger privateKey;
        private ECPoint publicKey;

        public KeyPair() { }

        public KeyPair(BigInteger privateKey, ECPoint publicKey)
        {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }

        public void SetPrivateKey(BigInteger privateKey)
        {
            this.privateKey = privateKey;
        }

        public void SetPublicKey(ECPoint publicKey)
        {
            this.publicKey = publicKey;
        }

        public BigInteger GetPrivateKey()
        {
            return privateKey;
        }

        public ECPoint GetPublicKey()
        {
            return publicKey;
        }
    }
}
