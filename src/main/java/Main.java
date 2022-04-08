import javax.xml.bind.DatatypeConverter;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;
import java.security.*;
import java.util.Arrays;


public class Main {

    public static void main(String[] args) throws Exception {
        Assinatura assinatura = new Assinatura();
        File arquivo = new File("src/main/java/AFD.txt");

        //byte[] mensagem = new byte[(int) arquivo.length()];
        byte[] mensagem = Files.readAllBytes(arquivo.toPath());

        byte[] assinaturaDoc = assinatura.geraAssinatura(mensagem);

        System.out.println(" Mensagem : ");
        System.out.println(new String(mensagem, "UTF-8"));

        PublicKey pubKey = assinatura.getPubKey();

        System.out.println("assinaturaDoc byte : " + Arrays.toString(assinaturaDoc));
        String assinaturaTxt = DatatypeConverter.printBase64Binary(assinaturaDoc);
        System.out.println("assinaturaDoc string: " + assinaturaTxt);

        validaMensagem(pubKey, mensagem, assinaturaDoc);

        FileWriter fw = new FileWriter(arquivo, true);
        BufferedWriter bw = new BufferedWriter(fw);
        bw.newLine();
        bw.write(assinaturaTxt);

        bw.close();
        fw.close();

        System.out.println("Mensagem Assinada : ");
        System.out.println(Files.readString(arquivo.toPath()));

    }

    public static void validaMensagem(PublicKey pubKey, byte[] mensagem, byte[] assinatura) throws
            NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature clientSig = Signature.getInstance("MD5withRSA");
        clientSig.initVerify(pubKey);
        clientSig.update(mensagem);

        if (clientSig.verify(assinatura)) {
            System.out.println("A Mensagem recebida foi assinada corretamente.");
        } else {
            System.out.println("A Mensagem recebida NÃO pode ser validada.");
        }
    }


}
