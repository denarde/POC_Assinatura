import java.security.*;

public class Assinatura {

        private PublicKey pubKey;
        private PrivateKey priKey;

        public PublicKey getPubKey() {
            return pubKey;
        }

        public void setPubKey(PublicKey pubKey) {
            this.pubKey = pubKey;
        }

        public PrivateKey getPriKey() {
            return priKey;
        }


        public byte[] geraAssinatura(byte[] mensagem) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

            Signature sig = Signature.getInstance("DSA");

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");

            SecureRandom secRan = new SecureRandom();
            kpg.initialize(512, secRan);
            KeyPair keyP = kpg.generateKeyPair();

            this.pubKey = keyP.getPublic();
            PrivateKey priKey = keyP.getPrivate();

            sig.initSign(priKey);

            sig.update(mensagem);
            byte[] assinatura = sig.sign();

            return assinatura;

        }

}
