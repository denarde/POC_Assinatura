import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.encryption.InvalidPasswordException;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.demoiselle.signer.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.core.keystore.loader.factory.KeyStoreLoaderFactory;
import org.demoiselle.signer.cryptography.DigestAlgorithmEnum;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory;
import org.demoiselle.signer.policy.impl.cades.SignerAlgorithmEnum;
import org.demoiselle.signer.policy.impl.pades.pkcs7.impl.PAdESSigner;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.KeyStore.Builder;
import java.security.cert.Certificate;
import java.util.Calendar;
import java.util.Enumeration;


public class AssinaPdfLib {

    public void testComFile() {

        // INFORMAR o arquivo de entrada
        //
        String fileDirName = "src/main/java/ticket-report13740479054277737171.pdf";
        //String fileDirName = "/";
        byte[] fileToSign = readContent(fileDirName);

        // INFORMAR o nome do arquivo de saida assinado
        //
        //String fileDirName = "C:\\Users\\{usuario}\\arquivo_assinado";

        String filePDFAssinado = "src/main/java/ticket-report13740479054277737171_assinado.pdf";

        try {
            this.doSigner(fileToSign, filePDFAssinado);
        } catch (Throwable e) {
            e.printStackTrace();
            //assertTrue(false);
        }
        //assertTrue(true);
    }

    private void doSigner(byte[] toSign, final String signedFile) throws Throwable {

        FileOutputStream fos = new FileOutputStream(signedFile);
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        byte[] hashOriginal = md.digest(toSign);
        String hashOriginalToHex = org.bouncycastle.util.encoders.Hex.toHexString(hashOriginal);
        BigInteger bigId = new BigInteger(hashOriginalToHex.toUpperCase(), 16);
        PDSignature signature = new PDSignature();
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        //Calendar calendar = Calendar.getInstance();
        //calendar.set(Calendar.HOUR_OF_DAY, 0);
        //calendar.set(Calendar.MINUTE, 0);
        //calendar.set(Calendar.SECOND, 0);
        //calendar.set(Calendar.MILLISECOND, 0);
        //signature.setSignDate(calendar);


        Calendar.getInstance();
        PDDocument original = PDDocument.load(toSign);
        original.setDocumentId(bigId.longValue());
        original.addSignature(signature, new SignatureInterface() {
            public byte[] sign(InputStream contentToSign) throws IOException {

                byte[] byteContentToSign = IOUtils.toByteArray(contentToSign);
                try {
                    java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-512");
                    // gera o hash do arquivo
                    // devido a uma restrição do token branco, no windws só funciona com 256
                    if (org.demoiselle.signer.core.keystore.loader.configuration.Configuration.getInstance().getSO().toLowerCase().indexOf("indows") > 0) {
                        md = java.security.MessageDigest.getInstance(DigestAlgorithmEnum.SHA_256.getAlgorithm());
                    }
                    byte[] hashToSign = md.digest(byteContentToSign);
                    String hashToSignHex = org.bouncycastle.util.encoders.Hex.toHexString(hashToSign);
                    System.out.println("hashPDFtoSign: " + hashToSignHex);

                    //windows e NeoID
                    //KeyStore ks = getKeyStoreTokenBySigner();

                    //KeyStore ks = getKeyStoreToken();

                    // para arquivo
                    KeyStore ks = getKeyStoreFileBySigner();

                    // para timeStamp

                    //KeyStore ksToTS = getKeyStoreTokenBySigner();

                    String alias = getAlias(ks);

                    //String aliasTS = getAlias(ksToTS);

                    PAdESSigner signer = new PAdESSigner();
                    signer.setCertificates(ks.getCertificateChain(alias));
                    //signer.setCertificatesForTimeStamp(ksToTS.getCertificateChain(aliasTS));

                    // para token
                    //signer.setPrivateKey((PrivateKey) ks.getKey(alias, null));

                    // para arquivo
                    char[] senhaArquivo = "1234".toCharArray();
                    signer.setPrivateKey((PrivateKey) ks.getKey(alias, senhaArquivo));

                    //signer.setSignaturePolicy(PolicyFactory.Policies.AD_RB_PADES_1_1);
                    // com carimbo de tempo

                    //signer.setPrivateKeyForTimeStamp((PrivateKey) ksToTS.getKey(aliasTS, null));
                    //signer.setSignaturePolicy(PolicyFactory.Policies.AD_RT_CADES_2_3);

                    signer.setSignaturePolicy(PolicyFactory.Policies.AD_RB_CADES_2_3);
                    // para mudar o algoritimo conforme o sistema operacional
                    // devido a uma restrição do token branco, no windows só funciona com 256
                    signer.setAlgorithm(SignerAlgorithmEnum.SHA512withRSA);
                    if (org.demoiselle.signer.core.keystore.loader.configuration.Configuration.getInstance().getSO().toLowerCase().indexOf("indows") > 0) {
                        signer.setAlgorithm(SignerAlgorithmEnum.SHA256withRSA);
                    }

                    byte[] assinatura = signer.doHashSign(hashToSign);

                    return assinatura;
                } catch (Throwable error) {
                    error.printStackTrace();
                    return null;
                }
            }
        });
        original.saveIncremental(fos);
        original.close();
    }


    // Usa o Signer para leitura, funciona para windows e NeoID
    private KeyStore getKeyStoreTokenBySigner() {

        try {

            KeyStoreLoader keyStoreLoader = KeyStoreLoaderFactory.factoryKeyStoreLoader();
            KeyStore keyStore = keyStoreLoader.getKeyStore();

            return keyStore;

        } catch (Exception e1) {
            e1.printStackTrace();
            return null;
        } finally {
        }

    }


    /**
     * Faz a leitura do token em LINUX, precisa setar a lib (.SO) e a senha do token.
     */

    private byte[] doHash(byte[] toSign) throws NoSuchAlgorithmException, InvalidPasswordException, IOException {

        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        byte[] hashOriginal = md.digest(toSign);
        String hashOriginalToHex = org.bouncycastle.util.encoders.Hex.toHexString(hashOriginal);
        BigInteger bigId = new BigInteger(hashOriginalToHex.toUpperCase(), 16);
        PDSignature signature = new PDSignature();
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        PDDocument original;
        original = PDDocument.load(toSign);
        original.setDocumentId(bigId.longValue());
        original.addSignature(signature);
        ExternalSigningSupport externalSigningSupport = original.saveIncrementalForExternalSigning(null);
        InputStream contentToSign = externalSigningSupport.getContent();
        byte[] byteContentToSign = IOUtils.toByteArray(contentToSign);

        String StringbyteContentToSign = new String(Base64.encodeBase64(byteContentToSign));
        System.out.println("StringbyteContentToSign: " + StringbyteContentToSign);
        md = java.security.MessageDigest.getInstance("SHA-512");
        // devido a uma restrição do token branco, no windws só funciona com 256
        //if (org.demoiselle.signer.core.keystore.loader.configuration.Configuration.getInstance().getSO().toLowerCase().indexOf("indows") > 0) {
        md = java.security.MessageDigest.getInstance(DigestAlgorithmEnum.SHA_256.getAlgorithm());
        //}
        byte[] hashToSign = md.digest(byteContentToSign);
        //String hashToSingHex = org.bouncycastle.util.encoders.Hex.toHexString(hashToSign);
        String hashToSignEncoded = new String(Base64.encodeBase64(hashToSign));
        //System.out.println("hashToSignEncoded: "+hashToSignEncoded);
        original.close();
        return hashToSign;


    }

    private byte[] signHash(byte[] hashToSign) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        //windows e NeoID
        KeyStore ks = getKeyStoreTokenBySigner();

        //KeyStore ks = getKeyStoreToken();
        String alias = getAlias(ks);

        PAdESSigner signer = new PAdESSigner();
        signer.setCertificates(ks.getCertificateChain(alias));

        // para token
        signer.setPrivateKey((PrivateKey) ks.getKey(alias, null));

        signer.setSignaturePolicy(PolicyFactory.Policies.AD_RB_PADES_1_1);
        // com carimbo de tempo
        //signer.setSignaturePolicy(PolicyFactory.Policies.AD_RT_PADES_1_1);

        // para mudar o algoritimo
        // devido a uma restrição do token branco, no windws só funciona com 256
        //signer.setAlgorithm(SignerAlgorithmEnum.SHA512withRSA);
        //if (org.demoiselle.signer.core.keystore.loader.configuration.Configuration.getInstance().getSO().toLowerCase().indexOf("indows") > 0) {
        signer.setAlgorithm(SignerAlgorithmEnum.SHA256withRSA);
        //}

        byte[] assinatura = signer.doHashSign(hashToSign);
        String StringAssinatura = new String(Base64.encodeBase64(assinatura));
        System.out.println(StringAssinatura);

        return assinatura;

    }

    /**
     * @param toSign
     * @param signature
     * @param signedFile
     * @throws InvalidPasswordException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */

    private void addSignature(byte[] toSign, byte[] signature, final String signedFile) throws InvalidPasswordException, IOException, NoSuchAlgorithmException {
        final byte[] varSignature = signature;
        FileOutputStream fileOut = new FileOutputStream(signedFile);
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        byte[] hashOriginal = md.digest(toSign);
        String hashOriginalToHex = org.bouncycastle.util.encoders.Hex.toHexString(hashOriginal);
        BigInteger bigId = new BigInteger(hashOriginalToHex.toUpperCase(), 16);
        PDSignature pdfSignature = new PDSignature();
        pdfSignature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        pdfSignature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        PDDocument original;
        original = PDDocument.load(toSign);
        original.setDocumentId(bigId.longValue());
        original.addSignature(pdfSignature);
        ExternalSigningSupport externalSigningSupport = original.saveIncrementalForExternalSigning(fileOut);
        externalSigningSupport.setSignature(signature);
        byte[] bytePdfSigned = Files.readAllBytes(Paths.get(signedFile));
        String pdfSignedEncoded = new String(Base64.encodeBase64(bytePdfSigned));
        original.close();
        fileOut.flush();
        fileOut.close();

    }


    private KeyStore getKeyStoreFileBySigner() {

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
        } finally {
        }

    }


    private String getAlias(KeyStore ks) {
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
                //System.out.println(""+ks.getKey(alias, null));
                certificates = ks.getCertificateChain(alias);
            }

        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return alias;
    }

    private byte[] readContent(String parmFile) {
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

    //@Test
    public void testGerarBase64FromFile() throws IOException {

        String fileToConvert = "/";

        byte[] fileConverted = readContent(fileToConvert);
        String S = Base64.encodeBase64String(fileConverted);


        File file = new File("/");
        FileOutputStream os = new FileOutputStream(file);
        os.write(S.getBytes());
        os.flush();
        os.close();

    }

}
