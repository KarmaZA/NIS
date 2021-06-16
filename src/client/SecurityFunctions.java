import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import java.util.Base64;

public class SecurityFunctions {
    public static void main(String[] args) {
    }

    public String PGPConfidentiality(String message, Key theirPublickey){
        String encryptedData = null;
        try {
            //zip
            String compressedMessage = compress(message);
            //encrypt with shared key

            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

//            BASE64Decoder b64 = new BASE64Decoder(); //normal level of encryptoon

            Key sharedKey = null; //TODO get shared key per sent message

            AsymmetricBlockCipher e = new RSAEngine();
            e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
//            e.init(true, theirPublickey); //original
//            e.init(true, sharedKey);

            byte[] messageBytes = compressedMessage.getBytes();
            byte[] hexEncodedCipher = e.processBlock(messageBytes, 0, messageBytes.length);
            //why are we encrypting it with the public key?

//            System.out.println(getHexString(hexEncodedCipher));
//            encryptedData = getHexString(hexEncodedCipher);

        }
        catch (Exception e) {
            System.out.println(e);
        }

        return encryptedData;
//        return "";
    }

    public static byte[] encryptWithPublicKey (String message, Key PublicKey){
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            byte[] cipherText = null;
            // get an RSA cipher object and print the provider
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            System.out.println("The provider is: " + cipher.getProvider().getInfo());
            //encrypt the plaintext using the public key
            cipher.init(Cipher.ENCRYPT_MODE, PublicKey);
            cipherText = cipher.doFinal(message.getBytes());
//            return new String (cipherText);
            return cipherText;
        }

        catch (Exception e) {
            System.out.println(e);
        }
        //else
        return null;
    }

    public static String decryptWithPrivateKey(byte[] cipherText, Key key) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        try {
            byte[] dectyptedText = null; // decrypt the text using the private key
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, key);
            dectyptedText = cipher.doFinal(cipherText);
            System.out.println("String decrypted");
            return new String (dectyptedText);
        }
        catch (Exception e) {
            System.out.println(e);
        }
        return "";
    }

    public static String decrypt (String message,Key publickey, Key privatekey, Key sharedkey){
        return "";
    }

    public static int hash (String message){
        return message.hashCode();
    }

    public static String compress(String message) throws IOException { //assuming message is not null
        ByteArrayOutputStream out = new ByteArrayOutputStream(); //the output stream
        GZIPOutputStream gzip = new GZIPOutputStream(out); //another stream
        gzip.write(message.getBytes()); //write the message to the output stream
        gzip.close(); //so it is no longer open
        return out.toString("ISO-8859-1");
    }
    public static String deCompress (String message) throws IOException {
        GZIPInputStream gis = new GZIPInputStream(new ByteArrayInputStream(message.getBytes("ISO-8859-1")));
        BufferedReader bf = new BufferedReader(new InputStreamReader(gis, "ISO-8859-1"));
        String outStr = "";
        String line;
        while ((line=bf.readLine())!=null) {
            outStr += line;
        }
        return outStr;
    }
}
