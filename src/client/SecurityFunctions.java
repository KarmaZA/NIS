import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import java.util.Base64;

public class SecurityFunctions {

    private static byte[] IV;


    /**
     * PGP encryption to authenticate the sender.
     * @param message Message to send
     * @param privateKey Private key of sender
     * @return A signed hash and the original message, concatenated together
     * @throws NoSuchAlgorithmException
     */
    public static byte[] PGPAuthenticationEncrypt(String message, SecretKey privateKey) throws NoSuchAlgorithmException {
        //commented examples assume Alice is sending to Bob
        //hash the message
        String hashedMessage = hashString(message);
        //encrypt the hash with Alice's private key
        byte[] encryptedHash = encryptWithAsymmetricKey(hashedMessage,privateKey); //encrypt with private key
        //concatenate the encryptedHash and the original message
        byte[] encryptionAndMessage = concatenateArrays(encryptedHash, message.getBytes());
        return encryptionAndMessage;
    }

    /**
     * PGP decryption to authenticate sender.
     * @param concatMessage The signed hash and the message
     * @param publicKey The public key of the sender
     * @return The message only
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     */
    public static String PGPAuthenticationDecrypt(byte[] concatMessage, SecretKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        //commented examples assume Alice is sending to Bob
        //get two parts of message
        byte[] sharedKeyEncrypted = getKeyFromArray(concatMessage);
        byte[] messageOnly = getMessageFromArray(concatMessage);

        //decrypt the hash with Alice's public key
        String decryptedHash = decryptWithAsymmetriceKey(sharedKeyEncrypted,publicKey); //decrypt with  public key
        String hashMessageForComparison = hashString(new String(messageOnly));
        //compare the hash that was encrypted and the original message with the new hash if they match then we ensure confidentiality
        if(decryptedHash.equals(hashMessageForComparison))
        {
            System.out.println("Message received is from expected user (authentication successful).");
            return new String(messageOnly);
        }
        else{
            System.out.println("Failed to authenticate. Message may not be from expected user.");
        }
        return "Failed";
    }

    /**
     * PGP encryption for confidentiality
     * The message is compressed and encrypted with the shared key
     * Then the shared key is encrypted with the public key of the reciever, and concatenated to the message
     * @param message The message to encrypt
     * @param sharedKey The shared key between Alice and Bob
     * @param publicKey The receiver's public key
     * @return A compressed and encrypted (with shared key) version of the message, concatenated to the shared key (encrypted with the public key)
     * @throws IOException
     */
    public static byte[] PGPConfidentialityEncrypt(String message, SecretKey sharedKey, Key publicKey) throws IOException {
        try {
            //compress
            String compressedMessage = compress(message);

            //encrypt this message with the shared key
            byte[] encryptedCompressedMessage = encryptWithSharedKey(compressedMessage.getBytes(), sharedKey);

            //make key a string and encrypt with receiver's public Key
            String keyString =  new String(Base64.getEncoder().encode(sharedKey.getEncoded()));
            byte[] encryptedSharedKey = encryptWithAsymmetricKey(keyString, publicKey);

            System.out.println("Encrypted message with PGP");
            //send concatenation
            return concatenateArrays(encryptedSharedKey, encryptedCompressedMessage);
        }
        catch (Exception e) {
            System.out.println(e);
        }
        return null;
    }

    /**
     * PGP decryption for confidentiality
     * @param encrypted The shared key and encrypted compressed message
     * @param privateKey The private key of the receiver
     * @return the decrypted message
     * @throws IOException
     */
    public static String PGPConfidentialityDecrypt(byte[] encrypted, Key privateKey) throws IOException {
        try {
            //get the two parts of the message:
            byte[] sharedKeyEncrypted = getKeyFromArray(encrypted);
            byte[] encryptedMessageOnly = getMessageFromArray(encrypted);

            //get shared key
            String decryptedSharedKeyString = decryptWithAsymmetriceKey(sharedKeyEncrypted,privateKey);
            byte[] keyAsBytes = Base64.getDecoder().decode(decryptedSharedKeyString);
            SecretKey sharedKey = new SecretKeySpec(keyAsBytes,0,keyAsBytes.length, "AES");

            System.out.println("Extracted shared key: " + Base64.getEncoder().encodeToString(sharedKey.getEncoded())); //debug statement

            String decryptedCompressedMessage = decryptWithSharedKey(encryptedMessageOnly,sharedKey);

            String finalOutput = deCompress(decryptedCompressedMessage);

            return finalOutput;

        }
        catch (Exception e) {
            System.out.println(e);
        }
        return null;

    }

    /**
     * Concatenates two byte arrays
     * @param arr1 first array
     * @param arr2 second array
     * @return a single array containing both arrays
     */
    public static byte[] concatenateArrays(byte[] arr1, byte[] arr2){
        byte[] finByteArr = new byte[arr1.length+arr2.length];
        for(int i = 0; i < arr1.length; i++){
            finByteArr[i]=arr1[i];
        }
        for(int j = arr1.length; j < arr2.length+arr1.length; j++) {
            finByteArr[j]=arr2[j-arr1.length];

        }
        return finByteArr;
    }

    /**
     * Returns the key part of the confidentiality message
     * @param arr Full array
     * @return just the key
     */
    public static byte[] getKeyFromArray(byte[] arr) {
        byte[] sharedKeyEncrypted = new byte[128];
        for(int i=0; i< 128; i++) {
            sharedKeyEncrypted[i] = arr[i];

        }
        return sharedKeyEncrypted;

    }

    /**
     * Returns the message part of the confidentiality message
     * @param arr Full array
     * @return just the message
     */
    public static byte[] getMessageFromArray(byte[] arr){
        byte[] encryptedMessageOnly = new byte[arr.length-128];

        for(int j=128; j<arr.length; j++){
            encryptedMessageOnly[j-128]= arr[j];

        }
        return encryptedMessageOnly;
    }


    /**
     * Encryption using a shared key
     * @param message Message to encrypt
     * @param sharedKey The shared key
     * @return an encrypted version of the message
     */
    public static byte[] encryptWithSharedKey(byte[] message, SecretKey sharedKey)
    {
        try{
            if (IV==null){ //If IV does not exist, make one here
                IV=KeyGenerator.genIV();
            }
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); //cipher instance
            SecretKeySpec keySpecification = new SecretKeySpec(sharedKey.getEncoded(), "AES"); //using AES akgorithm
            IvParameterSpec ivSpecification = new IvParameterSpec(IV); //make IvParameterSpec based on IV
            cipher.init(Cipher.ENCRYPT_MODE, keySpecification, ivSpecification); //we want to encrypt
            byte[] cipherText = cipher.doFinal(message); //perform encryption

            return cipherText;
        }
        catch (Exception e) {
            System.out.println(e);
        }
        return null;
    }


    /**
     * Decrypts a message with a shared key
     * @param cipherText Message to decrypt
     * @param sharedKey The shared key
     * @return the decrypted message
     * @throws Exception
     */
    public static String decryptWithSharedKey (byte[] cipherText, SecretKey sharedKey) throws Exception
    {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); //cipher instance
        SecretKeySpec keySpecification = new SecretKeySpec(sharedKey.getEncoded(), "AES"); //using AES algorithm
        IvParameterSpec ivSpecification = new IvParameterSpec(IV); //based on same IV as used in encryption
        cipher.init(Cipher.DECRYPT_MODE, keySpecification, ivSpecification); //we want to decrypt
        byte[] decryptedText = cipher.doFinal(cipherText); //decrypt the message
        return new String(decryptedText);
    }


    /**
     * Encrypts with either sender's private key, or receiver's public key - depending on whether encrypt for authentication or for confidentiality
     * @param message Message to encrypt
     * @param asymmetricKey Key to encrypt with
     * @return Encrypted message
     */
    public static byte[] encryptWithAsymmetricKey(String message, Key asymmetricKey){
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); //RSA cipher object
            System.out.println("The security provider is: " + cipher.getProvider().getInfo());
            cipher.init(Cipher.ENCRYPT_MODE, asymmetricKey); //encrypting mode
            byte[] cipherText = cipher.doFinal(message.getBytes()); //encrypt
            return cipherText;
        }
        catch (Exception e) {
            System.out.println(e);
        }
        return null; //if failed
    }

    /**
     * Decrypts with either receiver's private key, or sender's public key - depending on whether encrypt for authentication or for confidentiality
     * @param cipherText Message to decrypt
     * @param asymmetricKey Key to decrypt with
     * @return Decrypted version of message
     */
    public static String decryptWithAsymmetriceKey(byte[] cipherText, Key asymmetricKey) {
        try {
            byte[] dectyptedText = null; // decrypt the text using the private key
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, asymmetricKey);
            dectyptedText = cipher.doFinal(cipherText);
            System.out.println("String decrypted");
            return new String (dectyptedText);
        }
        catch (Exception e) {
            System.out.println(e);
        }
        return null; //if failed
    }



    /**
     * Hashing algorithm used to hash a message.
     * @param message message to hash
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static String hashString(String message) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] hash = messageDigest.digest(message.getBytes(StandardCharsets.UTF_8));
        return  new String(Hex.encode(hash));
    }

    /**
     * Compress a given message
     * @param message Message to compress
     * @return A compressed version of the message
     * @throws IOException
     */
    public static String compress(String message) throws IOException { //assuming message is not null
        //set up streams
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        GZIPOutputStream gzip = new GZIPOutputStream(out);
        //create compressed version
        gzip.write(message.getBytes()); //write the message to the output stream
        gzip.close();
        return out.toString("ISO-8859-1");
    }

    /**
     * Decompress a given message
     * @param compressed Compressed message
     * @return Decompressed version of the message
     * @throws IOException
     */
    public static String deCompress (String compressed) throws IOException {
        //set up stream and reader
        GZIPInputStream gzipInputStream = new GZIPInputStream(new ByteArrayInputStream(compressed.getBytes("ISO-8859-1")));
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(gzipInputStream, "ISO-8859-1"));

        //create message
        String toReturn = "";
        String line;
        while ((line=bufferedReader.readLine())!=null) { //per line of reader
            toReturn += line;
        }
        return toReturn;
    }


}