import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.zip.Deflater;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import java.util.Base64;
import java.util.zip.Inflater;

public class SecurityFunctions {

    private static byte[] IV;

    public static byte[] PGPFullEncrypt(byte[] toEncrypt, SecretKey sharedKey, Key senderPrivate, Key receiverPublic ) throws NoSuchAlgorithmException, IOException {
        byte[] pgpAuth = PGPAuthenticationEncrypt(new String(toEncrypt), senderPrivate);
        byte[] pgpConfid = PGPConfidentialityEncrypt(new String(pgpAuth), sharedKey, receiverPublic);
        return pgpConfid;
    }

    public static byte[] PGPFullDecrypt(byte[] encrypted, Key receiverPrivate , Key senderPublic) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] pgpConfidDecrypt = PGPConfidentialityDecrypt(encrypted, receiverPrivate).getBytes();

        byte[] pgpAuthDecrypt = PGPAuthenticationDecrypt(pgpConfidDecrypt, senderPublic);
        return pgpAuthDecrypt;
    }

    /**
     * PGP encryption to authenticate the sender.
     * @param message Message to send
     * @param privateKey Private key of sender
     * @return A signed hash and the original message, concatenated together
     * @throws NoSuchAlgorithmException
     */
    public static byte[] PGPAuthenticationEncrypt(String message, Key privateKey) throws NoSuchAlgorithmException {
        //commented examples assume Alice is sending to Bob
        //hash the message
        String hashedMessage = hashString(message);
        System.out.print("Hash string length is ");
        System.out.println(hashedMessage.length());
        //encrypt the hash with Alice's private key
        byte[] encryptedHash = encryptWithAsymmetricKey(hashedMessage,privateKey); //encrypt with private key
        System.out.print("Hash encrypted length is ");
        System.out.println(encryptedHash.length);

        //why hash weird characters?

        //concatenate the encryptedHash and the original message
        byte[] encryptionAndMessage = concatenateArrays(encryptedHash, message.getBytes());
        return encryptionAndMessage;
    }

    /**
     * PGP decryption to authenticate sender.
     * @param concatMessage The signed hash and the message
     * @param senderPublicKey The public key of the sender
     * @return The message only if authenticated. returns null if not authenticated
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     */
    public static byte[] PGPAuthenticationDecrypt(byte[] concatMessage, Key senderPublicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        //commented examples assume Alice is sending to Bob
        //get two parts of message
        byte[] encryptedHashOnly = getPartFromArray(concatMessage,0,128);
        byte[] messageOnly = getPartFromArray(concatMessage,128, concatMessage.length);
        System.out.println("message only is " + new String(messageOnly));


        //decrypt the hash with Alice's public key
        String decryptedHash = decryptWithAsymmetricKey(encryptedHashOnly,senderPublicKey); //decrypt with  public key
        //System.out.println("Hash only is " + new String (decryptedHash));
        String hashMessageForComparison = hashString(new String(messageOnly));
        //compare the hash that was encrypted and the original message with the new hash if they match then we ensure confidentiality

        if(decryptedHash==null){
            System.out.println("why is it null?");
            return messageOnly;
        }
        if(decryptedHash.equals(hashMessageForComparison))
        {
            System.out.println("Message received is from expected user (authentication successful).");
            return messageOnly;
        }
        else{
            System.out.println("Failed to authenticate. Message may not be from expected user.");
        }
        return null; //dont return message if not authenticated
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
            //String compressedMessage = new String(newcompress(message)); //new compression method

            //encrypt this message with the shared key
            byte[] encryptedCompressedMessage = encryptWithSharedKey(compressedMessage.getBytes(), sharedKey);

            //make key a string and encrypt with receiver's public Key
            String keyString =  new String(Base64.getEncoder().encode(sharedKey.getEncoded()));
            byte[] encryptedSharedKey = encryptWithAsymmetricKey(keyString, publicKey);

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
            byte[] sharedKeyEncrypted = getPartFromArray(encrypted,0,128);
            byte[] encryptedMessageOnly = getPartFromArray(encrypted,128,encrypted.length);
            //get shared key
            String decryptedSharedKeyString = decryptWithAsymmetricKey(sharedKeyEncrypted,privateKey);
            byte[] keyAsBytes = Base64.getDecoder().decode(decryptedSharedKeyString);
            SecretKey sharedKey = new SecretKeySpec(keyAsBytes,0,keyAsBytes.length, "AES");

            System.out.println("Extracted shared key: " + Base64.getEncoder().encodeToString(sharedKey.getEncoded())); //debug statement

            String decryptedCompressedMessage = decryptWithSharedKey(encryptedMessageOnly,sharedKey);

            String finalOutput = deCompress(decryptedCompressedMessage);
           // String finalOutput = newdecompress(decryptedCompressedMessage.getBytes(),20); // new decompression function //TODO make num generic.

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
     * returns a part of a byte array
     * @param arr Full array
     * @param from Starting index (included)
     * @param to Ending index (excluded)
     * @return The requested part
     */
    public static byte[] getPartFromArray(byte[] arr, int from, int to){ //from including, to excluding
        byte[] toReturn = new byte[to-from];
        for(int i=from; i< to; i++) {
            toReturn[i-from] = arr[i];
        }
        return toReturn;
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
            System.out.println("Encrypted with shared key");
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
        System.out.println("Decrypted with shared key");
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
            System.out.println("Encrypted with asymmetric key");
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
    public static String decryptWithAsymmetricKey(byte[] cipherText, Key asymmetricKey) {
        try {
            byte[] dectyptedText = null; // decrypt the text using the private key
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, asymmetricKey);
            dectyptedText = cipher.doFinal(cipherText);
            System.out.println("Decrypted with asymmetric key");
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
        byte[] hash = messageDigest.digest(message.getBytes(StandardCharsets.UTF_8)); //ISO or UTF
        //return  new String(Hex.encode(hash));
        return  new String(hash);
    }

    /**
     * Compress a given message
     * @param message Message to compress
     * @return A compressed version of the message
     * @throws IOException
     */
    public static String compress(String message) throws IOException { //assuming message is not null
        System.out.print("Compressing string of length ");
        System.out.println(message.length());
        //set up streams
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        GZIPOutputStream gzip = new GZIPOutputStream(out);
        //create compressed version
        gzip.write(message.getBytes()); //write the message to the output stream
        gzip.close();
        String toReturn = out.toString("ISO-8859-1");
        System.out.print("To length ");
        System.out.println(toReturn.length());
        return toReturn;
    }

    /**
     * Decompress a given message
     * @param compressed Compressed message
     * @return Decompressed version of the message
     * @throws IOException
     */
    public static String deCompress (String compressed) throws IOException {
        System.out.print("Decompressing string of length ");
        System.out.println(compressed.length());

        //set up stream and reader
        GZIPInputStream gzipInputStream = new GZIPInputStream(new ByteArrayInputStream(compressed.getBytes("ISO-8859-1")));
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(gzipInputStream, "ISO-8859-1"));

        //create message
        String toReturn = "";
        String line;
        while ((line=bufferedReader.readLine())!=null) { //per line of reader
            toReturn += line;
        }

        System.out.print("To length ");
        System.out.println(toReturn.length());
        return toReturn;
    }

    public static byte[] newcompress(String toCompress){
        try {
            // Encode a String into bytes
            byte[] input = toCompress.getBytes("UTF-8");

            // Compress the bytes
            byte[] output = new byte[100]; //wont this limit the length?
            Deflater compresser = new Deflater();
            compresser.setInput(input);
            compresser.finish();
            int compressedDataLength = compresser.deflate(output);
            System.out.print("compressed data length ");
            System.out.println(compressedDataLength);
            compresser.end();

            return output; //some say to encode to string using base 64

        } catch(java.io.UnsupportedEncodingException ex) {
            // handle
        }
        return null;
    }

    public static String newdecompress(byte[] compressed, int compressedDataLength){
        try {
            // Decompress the bytes
            Inflater decompresser = new Inflater();
            decompresser.setInput(compressed, 0, compressedDataLength);
            byte[] result = new byte[100];
            int resultLength = decompresser.inflate(result);
            decompresser.end();

            // Decode the bytes into a String
            String outputString = new String(result, 0, resultLength, "UTF-8");
            System.out.println("returning decompressed string of length ");
            System.out.println(outputString.length());
            return outputString;


        } catch(java.io.UnsupportedEncodingException ex) {
            System.out.println(ex);
            // handle
        } catch (java.util.zip.DataFormatException ex) {
            System.out.println(ex);
            // handle
        }
        return null;
    }

}