import org.apache.commons.codec.binary.Base64;
import org.demoiselle.signer.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.core.keystore.loader.factory.KeyStoreLoaderFactory;
import org.demoiselle.signer.policy.impl.cades.SignerAlgorithmEnum;
import org.demoiselle.signer.policy.impl.cades.factory.PKCS7Factory;
import org.demoiselle.signer.policy.impl.cades.pkcs7.PKCS7Signer;
import org.demoiselle.signer.timestamp.configuration.TimeStampConfig;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Enumeration;

public class AssinaTxtLib {

    // Usa o Signer para leitura, funciona para windows e NeoID
    private static KeyStore getKeyStoreTokenBySigner() {

        try {

            KeyStoreLoader keyStoreLoader = KeyStoreLoaderFactory.factoryKeyStoreLoader();
            KeyStore keyStore = keyStoreLoader.getKeyStore();

            return keyStore;

        } catch (Exception e1) {
            e1.printStackTrace();
            return null;
        }
    }

    private static String getAlias(KeyStore ks) {
        Certificate[] certificates = null;
        String alias = "";
        Enumeration<String> e;
        try {
            e = ks.aliases();
            while (e.hasMoreElements()) {
                alias = e.nextElement();
                System.out.println("alias..............: " + alias);
                System.out.println("iskeyEntry" + ks.isKeyEntry(alias));
                System.out.println("containsAlias" + ks.containsAlias(alias));
                certificates =  ks.getCertificateChain(alias);
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return alias;
    }

    private static byte[] readContent(String parmFile) {
        byte[] result = null;
        try {
            File file = new File(parmFile);
            FileInputStream is = new FileInputStream(parmFile);
            result = new byte[(int) file.length()];
            is.read(result);
            is.close();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        return result;
    }

    private static KeyStore getKeyStoreFileBySigner() {

        try {


            // informar o caminho e nome do arquivo
            File filep12 = new File("src/main/java/certificado/WayneEnterprisesInc.pfx");


            KeyStoreLoader loader = KeyStoreLoaderFactory.factoryKeyStoreLoader(filep12);
            // Informar a senha
            KeyStore keystore = loader.getKeyStore("1234");
            return keystore;

        } catch (Exception e1) {
            e1.printStackTrace();
            return null;
        }
    }

    public static void assinaTxtLib(){
        try {

            System.out.println("******** TESTANDO COM ARQUIVO *****************");

            // INFORMAR o arquivo

            //
            //String fileDirName = "src/main/java/AFD.txt";
            String fileDirName = "src/main/java/report15221432020320212189.xls";
            //String fileDirName = "/tmp/";
            byte[] fileToSign;

            //fileToSign = Base64.decodeBase64("VGVzdGUgQXNzaW5hdHVyYQo=");
            // se informar o fileDirName decomentar abaixo
            fileToSign = readContent(fileDirName);


            // MSCAPI off
            //org.demoiselle.signer.core.keystore.loader.configuration.Configuration.setMSCAPI_ON(false);

            // Setar Proxy
            // Proxy.setProxyEndereco("localhost");
            //Proxy.setProxyPorta("3128");
            //Proxy.setProxySenha("senha");
            //Proxy.setProxyUsuario("usuario");
            //Proxy.setProxy();


            // Para certificado NeoID e windows token
            //KeyStore ks = getKeyStoreTokenBySigner();

            //// Para certificado em arquivo A1
            KeyStore ks = getKeyStoreFileBySigner();
            // Keystore diferente para timestamp
            //KeyStore ksToTS = getKeyStoreStreamBySigner();
            // Para certificado token Linux
            //KeyStore ks = getKeyStoreToken();

            // Para certificados no so windows (mascapi)
            // KeyStore ks = getKeyStoreOnWindows();

            String alias = getAlias(ks);
            //String aliasToTs = getAlias(ksToTS);
            //char[] senhaTS = "senha".toCharArray();
            /* Parametrizando o objeto doSign */
            PKCS7Signer signer = PKCS7Factory.getInstance().factoryDefault();

            signer.setCertificates(ks.getCertificateChain(alias));

            // para token
            //signer.setPrivateKey((PrivateKey) ks.getKey(alias, null));

            // para arquivo
            // quando certificado em arquivo, precisa informar a senha
            char[] senha = "1234".toCharArray();
            signer.setPrivateKey((PrivateKey) ks.getKey(alias, senha));

            // politica referencia básica sem carimbo de tempo
            //signer.setSignaturePolicy(PolicyFactory.Policies.AD_RB_CADES_2_3);
            // com carimbo de tempo
            //signer.setSignaturePolicy(PolicyFactory.Policies.AD_RT_CADES_2_3);
            // pode ser outro certificado para timestamp
            //signer.setCertificatesForTimeStamp(ksToTS.getCertificateChain(aliasToTs));
            //signer.setPrivateKeyForTimeStamp((PrivateKey) ksToTS.getKey(aliasToTs, senhaTS));

            // referencia de validação
            //signer.setSignaturePolicy(PolicyFactory.Policies.AD_RV_CADES_2_3);
            // para mudar o algoritimo
            signer.setAlgorithm(SignerAlgorithmEnum.SHA512withRSA);
            String varSO = System.getProperty("os.name");
            if (varSO.contains("indows")) {
                signer.setAlgorithm(SignerAlgorithmEnum.SHA512withRSA);
            }

            /* Realiza a assinatura do conteudo */
            System.out.println("Efetuando a  assinatura do conteudo");
            // Assinatura desatachada

            // Cache de cadeia
            //CAManagerConfiguration config = CAManagerConfiguration.getInstance();
            //config.setCached(true);
            //org.demoiselle.signer.core.ca.manager.CAManagerConfiguration.getInstance().setCached(true);

            //Cache LCR
            //ConfigurationRepo configs= ConfigurationRepo.getInstance();
            //configs.setCrlIndex("crl_index");
            //configs.setCrlPath("/tmp/lcr_cache/");
            //configs.setOnline(false);
            //configs.setValidateLCR(false);


            // Diretorio LPA
            //ConfigurationRepo config = ConfigurationRepo.getInstance();
            //config.setLpaPath("/home/signer/lpa/");
            // LPA online
            //config.setOnlineLPA(false);


            TimeStampConfig tsConfig = TimeStampConfig.getInstance();
            tsConfig.setTimeOut(100);
            tsConfig.setConnectReplay(2);
            byte[] signature = signer.doDetachedSign(fileToSign);
            String varSignature = Base64.encodeBase64String(signature);
            System.out.println(varSignature);
            //File file = new File("src/main/java/AFD_detached_rt.p7s");
            File file = new File("src/main/java/report15221432020320212189_detached_rt.p7s");
            FileOutputStream os = new FileOutputStream(file);
            os.write(signature);
            os.flush();
            os.close();
            System.out.println(signer.getSignatory());
            //System.out.println(DatatypeConverter.printBase64Binary(signature));
            //assertTrue(!signer.getSignatory().isEmpty());

        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | IOException ex) {
            ex.printStackTrace();
            //assertTrue(false);
        }
    }

}
