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

public class Encryption
{
    public static void main(String[] args)
    {
        //Read arguments array
        SecureRandom rand = new SecureRandom();
        String plainTextPath = args[0];
        String sideAKeyStorePath = args[1];
        char[] sideAKeyStorePassword = args[2].toCharArray();
        String sideAPrivateKeyAlias = args[3];
        String sideBCertificateAlias = args[4];
        String provider = "";
        boolean validProvider = false;
        if(args.length > 5)
        {
            provider = args[5];
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

        try{
            // read plain text file
            FileInputStream plainTextFile = new FileInputStream(plainTextPath);
            byte[] plainText = plainTextFile.readAllBytes();

            // load side A key store
            FileInputStream sideAKeyStoreFile = new FileInputStream(sideAKeyStorePath);
            KeyStore sideAKeyStore = KeyStore.getInstance("jks");
            sideAKeyStore.load(sideAKeyStoreFile, sideAKeyStorePassword);

            // init cipher symetric algorithm
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            SecretKey symetricKey = keyGenerator.generateKey();
            Cipher encyprtSymetricAlgorithm;
            if (validProvider)
            {
                encyprtSymetricAlgorithm = Cipher.getInstance("AES/CBC/PKCS5Padding", provider);
            }
            else
            {
                encyprtSymetricAlgorithm = Cipher.getInstance("AES/CBC/PKCS5Padding");
            }

            byte[] iv = new byte[16];
            rand.nextBytes(iv);
            encyprtSymetricAlgorithm.init(Cipher.ENCRYPT_MODE, symetricKey, new IvParameterSpec(iv));

            // encrypt plain text and write it to a file
            plainTextFile = new FileInputStream(plainTextPath);
            FileOutputStream enceyptedTextFile = new FileOutputStream("encryptedText.txt");
            CipherOutputStream cipherOutput = new CipherOutputStream(enceyptedTextFile, encyprtSymetricAlgorithm);
            byte[] b = new byte[8];
            int i = plainTextFile.read(b);
            while (i != -1)
            {
                cipherOutput.write(b,0, i);
                i = plainTextFile.read(b);
            }
            cipherOutput.close();
            enceyptedTextFile.close();
            plainTextFile.close();
            FileInputStream encryptedFile = new FileInputStream("encryptedText.txt");
            byte[] encryptedPlainText =  encryptedFile.readAllBytes();


            // init cipher asymetric algorithm
            Cipher encyprtAsymetricAlgorithm;
            if (validProvider)
            {
                encyprtAsymetricAlgorithm = Cipher.getInstance("RSA/ECB/PKCS1Padding", provider);
            }
            else
            {
                encyprtAsymetricAlgorithm = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            }

            Certificate cert = sideAKeyStore.getCertificate(sideBCertificateAlias);
            PublicKey sideBPublicKey = cert.getPublicKey();
            encyprtAsymetricAlgorithm.init(Cipher.ENCRYPT_MODE, sideBPublicKey);
            byte[] encryptedSymetricKey = encyprtAsymetricAlgorithm.doFinal(symetricKey.getEncoded());

            // create signature
            Signature signature = Signature.getInstance("SHA256withRSA");
            PrivateKey sideAPrivateKey = (PrivateKey)sideAKeyStore.getKey(sideAPrivateKeyAlias, sideAKeyStorePassword);
            signature.initSign(sideAPrivateKey);
            signature.update(encryptedPlainText);
            byte[] SignatureBytes = signature.sign();

            // export cipher algorithm parameters
            AlgorithmParameters symetricAlgorithmParams = encyprtSymetricAlgorithm.getParameters();

            // write to coniguration file
            String configurationFilePath = "configuration.txt";
            PrintWriter configurationFile = new PrintWriter(configurationFilePath);
            configurationFile.println(Base64.getEncoder().encodeToString(symetricAlgorithmParams.getEncoded()));
            configurationFile.println(Base64.getEncoder().encodeToString(SignatureBytes));
            configurationFile.println(Base64.getEncoder().encodeToString(encryptedSymetricKey));
            configurationFile.flush();
            configurationFile.close();
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IOException | KeyStoreException | CertificateException | SignatureException | UnrecoverableKeyException ex) {
            ex.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }

    }


}
