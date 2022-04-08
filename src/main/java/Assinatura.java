import java.io.FileInputStream;
import java.io.InputStream;
import java.security.*;

public class Assinatura {

    private PublicKey pubKey;
    private PrivateKey priKey;

    private char[] senha = "1234".toCharArray();

    private KeyStore rep;
    private String file = "src/main/java/certificado/WayneEnterprisesInc.pfx";

    public PublicKey getPubKey() {
        return pubKey;
    }

    public void setPubKey(PublicKey pubKey) {
        this.pubKey = pubKey;
    }

    public PrivateKey getPriKey() {
        return priKey;
    }


    public byte[] geraAssinatura(byte[] mensagem) throws Exception {

        Signature sig = Signature.getInstance("MD5withRSA");

        this.pubKey = getChavePublica();
        PrivateKey priKey = getChavePrivada();

        sig.initSign(priKey);

        sig.update(mensagem);
        byte[] assinatura = sig.sign();


        return assinatura;

    }

    public PrivateKey getChavePrivada() throws Exception {
        rep = KeyStore.getInstance("pkcs12");
        InputStream entrada = new FileInputStream(file);
        rep.load(entrada, senha);
        entrada.close();

        Key chavePrivada = (Key) rep.getKey("wayne enterprises, inc", senha);
        if (chavePrivada instanceof PrivateKey) {
            System.out.println("Chave Privada encontrada!");
            return (PrivateKey) chavePrivada;
        }
        return null;
    }

    public PublicKey getChavePublica() throws Exception {
        rep = KeyStore.getInstance("pkcs12");
        InputStream entrada = new FileInputStream(file);
        rep.load(entrada, senha);
        entrada.close();
        PublicKey chavePublica = rep.getCertificate("wayne enterprises, inc").getPublicKey();
        System.out.println("Chave Pública encontrada!");
        return chavePublica;
    }

}
