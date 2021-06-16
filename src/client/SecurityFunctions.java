import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import java.util.Base64;

public class SecurityFunctions {

    private static byte[] IV;

    public static void main(String[] args) throws IOException {
        //put this where use shared
//        if (IV==null){
//            IV=KeyGenerator.genIV();
//        }
        byte[] encryptedonPGP = PGPConfidentialityEncrypt("hello world", KeyGenerator.genSharedKey(), Alice.publicKey);
        String returned = PGPConfidentialityDecrypt(encryptedonPGP, Alice.privateKey);
        System.out.println(returned);
    }

    public static byte[] PGPConfidentialityEncrypt(String message, SecretKey sharedKey, Key publicKey) throws IOException {
        try {
            //zip
            String compressedMessage = compress(message);


            //encrypt this message with the shared key

            byte[] encryptedCompressedMessage = encryptWithSharedKey(compressedMessage.getBytes(), sharedKey);

            String keyString =  new String(Base64.getEncoder().encode(sharedKey.getEncoded()));
            byte[] encryptedSharedKey = encryptWithPublicKey(keyString, publicKey);

            //send concatenation
            return concatenateArrays(encryptedSharedKey, encryptedCompressedMessage);
        }
        catch (Exception e) {
            System.out.println(e);
        }
        return null;

    }

    public static String PGPConfidentialityDecrypt(byte[] encrypted, Key privateKey) throws IOException {
        try {
            //get thw two parts of the message
            System.out.println(encrypted);
            byte[] sharedKeyEncrypted = new byte[128];
            byte[] encryptedMessageOnly = new byte[encrypted.length-128];
            for(int i=0; i< 128; i++) {
                sharedKeyEncrypted[i] = encrypted[i];
            }
            for(int j=128; j<encrypted.length; j++){
                encryptedMessageOnly[j-128]= encrypted[j];
            }



            String decryptedSharedKeyString = decryptWithPrivateKey(sharedKeyEncrypted,privateKey);
            byte[] keyTEST = Base64.getDecoder().decode(decryptedSharedKeyString);

            SecretKey sharedKey = new SecretKeySpec(keyTEST,0,keyTEST.length, "AES");
            System.out.println("Extracted key");
            System.out.println(Base64.getEncoder().encodeToString(sharedKey.getEncoded()));

            String decryptedCompressedMessage = decryptWithSharedKey(encryptedMessageOnly,sharedKey);

            String finalOutput = deCompress(decryptedCompressedMessage);

            //this shows that the key to and from a string works
//        System.out.println("key:");
//        System.out.println(Base64.getEncoder().encodeToString(sharedKey.getEncoded()));
//        String keyString =  new String(Base64.getEncoder().encode(sharedKey.getEncoded()));
//        System.out.println("Key String");
//        System.out.println(keyString);
//        System.out.println("back to key");
//        byte[] encodedKey = Base64.getDecoder().decode(keyString);
//        Key key = new SecretKeySpec(encodedKey,0,encodedKey.length, "AES");
//        System.out.println(Base64.getEncoder().encodeToString(key.getEncoded()));


            return finalOutput;

        }
        catch (Exception e) {
            System.out.println(e);
        }
        return null;

    }

    public static byte[] concatenateArrays(byte[] arr1, byte[] arr2){
        byte[] finByteArr = new byte[arr1.length+arr2.length];
        for(int i = 0; i < arr1.length; i++){
            finByteArr[i]=arr1[i];
        }
        for(int j = arr1.length; j < arr2.length; j++) {
            finByteArr[j]=arr2[j-arr1.length];

        }
//        System.out.println("arr1: " + new String(arr1));
//        System.out.println("arr2: " + arr2);
//        System.out.println("makes" + finByteArr);
        return finByteArr;
    }

    public static byte[] encryptWithSharedKey(byte[] message, SecretKey sharedKey)// part of AES thing
    {
        try{
            if (IV==null){
                IV=KeyGenerator.genIV();
            }
            //Get Cipher Instance
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            //Create SecretKeySpec
            SecretKeySpec keySpec = new SecretKeySpec(sharedKey.getEncoded(), "AES");

            //Create IvParameterSpec
            IvParameterSpec ivSpec = new IvParameterSpec(IV);

            //Initialize Cipher for ENCRYPT_MODE
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

            //Perform Encryption
            byte[] cipherText = cipher.doFinal(message);

            return cipherText;
        }
        catch (Exception e) {
            System.out.println(e);
        }

        return null;
    }

    public static String decryptWithSharedKey (byte[] cipherText, SecretKey sharedKey) throws Exception
    {
        //Get Cipher Instance
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        //Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(sharedKey.getEncoded(), "AES");

        //Create IvParameterSpec
        IvParameterSpec ivSpec = new IvParameterSpec(IV);

        //Initialize Cipher for DECRYPT_MODE
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        System.out.println("here");
        //Perform Decryption
        byte[] decryptedText = cipher.doFinal(cipherText); //issue here for some reason

        System.out.println("here2"); //does not get here
        return new String(decryptedText);
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

    public static byte[] convertToByteArr(String message){
        return message.getBytes();
    }

    public static String hash(String message) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(message.getBytes(StandardCharsets.UTF_8));
        return  new String(Hex.encode(hash));
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
