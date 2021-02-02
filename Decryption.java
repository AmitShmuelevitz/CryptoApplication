import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Base64;

public class Decryption {

    public static void main(String args[]) throws Exception {

        //Read arguments array
        String encryptedTextPath = args[0];
        String ConfigurationTextPath = args[1];
        String sideBKeyStorePath = args[2];
        char[] sideBKeyStorePassword = args[3].toCharArray();
        String sideBPrivateKeyAlias = args[4];
        String sideACertificateAlias = args[5];
        String provider = "";
        boolean validProvider = false;
        if(args.length > 6)
        {
            provider = args[6];
        }

        //verify the provider
        if (!provider.equals(""))
        {
            for(Provider p : Security.getProviders())
            {
                String providerString = p.toString();
                if (provider.equals(providerString.substring(0, providerString.indexOf(" "))))
                {
                    validProvider = true;
                    break;
                }
            }
        }



        //Read configuration file
        File configurationFile = new File(ConfigurationTextPath);
        FileReader configurationReader = new FileReader(configurationFile);
        BufferedReader br = new BufferedReader(configurationReader);
        byte[] symetricAlgorithmParams = Base64.getDecoder().decode(br.readLine());
        byte[] SignatureBytes = Base64.getDecoder().decode(br.readLine());
        byte[] EncryptedSymetricKey = Base64.getDecoder().decode(br.readLine());
        br.close();

        //// load side B key store
        FileInputStream sideBKeyStoreFile = new FileInputStream(sideBKeyStorePath);
        KeyStore sideBKeyStore = KeyStore.getInstance("jks");
        sideBKeyStore.load(sideBKeyStoreFile, sideBKeyStorePassword);

        // init cipher asymetric algorithm
        PrivateKey sideBPrivateKey = (PrivateKey) sideBKeyStore.getKey(sideBPrivateKeyAlias, sideBKeyStorePassword);
        Cipher decyprtAsymetricAlgorithm;
        if (validProvider)
        {
            decyprtAsymetricAlgorithm = Cipher.getInstance("RSA/ECB/PKCS1Padding", provider);
        }
        else
        {
            decyprtAsymetricAlgorithm = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        }

        decyprtAsymetricAlgorithm.init(Cipher.DECRYPT_MODE, sideBPrivateKey);

        // decrypt the symetric key
        byte[] plainSymetricKeyBytes = decyprtAsymetricAlgorithm.doFinal(EncryptedSymetricKey);
        SecretKey plainSymetricKey = new SecretKeySpec(plainSymetricKeyBytes, 0, plainSymetricKeyBytes.length, "AES");

        // Load and initialize signature before verification
        Certificate cert = sideBKeyStore.getCertificate(sideACertificateAlias);
        PublicKey sideAPublicKey = cert.getPublicKey();
        Signature givenSignature = Signature.getInstance("SHA256withRSA");
        givenSignature.initVerify(sideAPublicKey);
        FileInputStream encryptedTextFile = new FileInputStream(encryptedTextPath);
        byte[] encryptedText = encryptedTextFile.readAllBytes();
        givenSignature.update(encryptedText);


        // Verify signature
        FileOutputStream decryptedTextFile = new FileOutputStream("decrypted.txt");
        if (givenSignature.verify(SignatureBytes))
        {
            // init algorithm parameters
            AlgorithmParameters algParams = AlgorithmParameters.getInstance("AES");
            algParams.init(symetricAlgorithmParams);

            // init cipher symetric algorithm
            Cipher decyprtSymetricAlgorithm;
            if(validProvider)
            {
                decyprtSymetricAlgorithm = Cipher.getInstance("AES/CBC/PKCS5Padding", provider);
            }
            else
            {
                decyprtSymetricAlgorithm = Cipher.getInstance("AES/CBC/PKCS5Padding");
            }

            decyprtSymetricAlgorithm.init(Cipher.DECRYPT_MODE, plainSymetricKey, algParams);

            // Decrypt text and write it to file
            encryptedTextFile = new FileInputStream(encryptedTextPath);
            CipherInputStream cipherInput = new CipherInputStream(encryptedTextFile, decyprtSymetricAlgorithm);
            byte[] b = new byte[8];
            int i = cipherInput.read(b);
            while (i != -1)
            {
                decryptedTextFile.write(b, 0, i);
                i = cipherInput.read(b);
            }

            decryptedTextFile.close();
            encryptedTextFile.close();
            cipherInput.close();
        }
        else
        {
            String execeptionMessage = "Signature Verification has failed";
            decryptedTextFile.write(execeptionMessage.getBytes());
            decryptedTextFile.close();
            throw new Exception(execeptionMessage);
        }

    }



    public Decryption() throws IOException, KeyStoreException {
    }


}
