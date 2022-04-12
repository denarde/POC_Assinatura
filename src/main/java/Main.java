import org.apache.commons.codec.binary.Base64;
import org.demoiselle.signer.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.core.keystore.loader.factory.KeyStoreLoaderFactory;
import org.demoiselle.signer.policy.impl.cades.SignerAlgorithmEnum;
import org.demoiselle.signer.policy.impl.cades.factory.PKCS7Factory;
import org.demoiselle.signer.policy.impl.cades.pkcs7.PKCS7Signer;
import org.demoiselle.signer.timestamp.configuration.TimeStampConfig;

import java.io.*;
import java.security.*;
import java.util.Enumeration;
import java.security.cert.Certificate;



public class Main {

    public static void main(String[] args) throws Exception {
        //AssinaSemLib.assinaSemLib();
        AssinaTxtLib.assinaTxtLib();
        AssinaPdfLib assinaPdf = new AssinaPdfLib();
        //assinaPdf.testComFile();

    }







}
