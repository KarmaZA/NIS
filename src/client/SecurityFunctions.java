import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import java.util.Base64;

public class SecurityFunctions {


    public static byte[] PGPFullEncrypt(byte[] toEncrypt, SecretKey sharedKey, Key senderPrivate, Key receiverPublic ) throws NoSuchAlgorithmException, IOException {
        byte[] pgpAuth = PGPAuthenticationEncrypt(toEncrypt, senderPrivate);
        return PGPConfidentialityEncrypt(pgpAuth, sharedKey, receiverPublic);
    }

    public static byte[] PGPFullDecrypt(byte[] encrypted, Key receiverPrivate , Key senderPublic) throws IOException,  NoSuchAlgorithmException {
        byte[] pgpConfidDecrypt = PGPConfidentialityDecrypt(encrypted, receiverPrivate);
        return PGPAuthenticationDecrypt(pgpConfidDecrypt, senderPublic);
    }

    /**
     * PGP encryption to authenticate the sender.
     * @param message Message to send
     * @param privateKey Private key of sender
     * @return A signed hash and the original message, concatenated together
     * @throws NoSuchAlgorithmException No such algorithm exception in PGPAuthenticationEncrypt
     */
    public static byte[] PGPAuthenticationEncrypt(byte[] message, Key privateKey) throws NoSuchAlgorithmException {
        //commented examples assume Alice is sending to Bob
        //hash the message
        System.out.println("Hashing the message for Authentication");
        String hashedMessage = hashString(message);



        //encrypt the hash with Alice's private key
        System.out.println("Encrypting the hash with the sender's private key");
        byte[] encryptedHash = encryptWithAsymmetricKey(hashedMessage,privateKey); //encrypt with private key

        //concatenate the encryptedHash and the original message
        return concatenateArrays(encryptedHash, message);
    }

    /**
     * PGP decryption to authenticate sender.
     * @param concatMessage The signed hash and the message
     * @param senderPublicKey The public key of the sender
     * @return The message only if authenticated. returns null if not authenticated
     * @throws NoSuchAlgorithmException No such algorithm at PGPAuthenticationDecrypt
     */
    public static byte[] PGPAuthenticationDecrypt(byte[] concatMessage, Key senderPublicKey) throws NoSuchAlgorithmException{
        //commented examples assume Alice is sending to Bob
        //get two parts of message
        byte[] encryptedHashOnly = getPartFromArray(concatMessage,0,128);
        byte[] messageOnly = getPartFromArray(concatMessage,128, concatMessage.length);

        System.out.println("Extracting the hash from the message, decrypting it with the sender's public key");
        //decrypt the hash with Alice's public key
        String decryptedHash = decryptWithAsymmetricKey(encryptedHashOnly,senderPublicKey); //decrypt with  public key
        //System.out.println("Hash only is " + new String (decryptedHash));
        System.out.println("Generating our own hash of the message");
        String hashMessageForComparison = hashString(messageOnly);
        //compare the hash that was encrypted and the original message with the new hash if they match then we ensure confidentiality

        System.out.println("Comparing received hash with a hash we generate");
        if(decryptedHash==null){
            System.out.println("the hash is null... this will likely cause issues.");
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
     */
    public static byte[] PGPConfidentialityEncrypt(byte[] message, SecretKey sharedKey, Key publicKey) {
        try {
            System.out.println("Compressing the message");
            //compress
            byte[] compressedMessage = compress(message);

            //encrypt this message with the shared key

            byte[] encryptedCompressedMessage = encryptWithSharedKey(compressedMessage, sharedKey);

            System.out.println("Encrypt the key with the receiver's public key");
            //make key a string and encrypt with receiver's public Key
            String keyString =  new String(Base64.getEncoder().encode(sharedKey.getEncoded()));
            byte[] encryptedSharedKey = encryptWithAsymmetricKey(keyString, publicKey);

            //send concatenation
            return concatenateArrays(encryptedSharedKey, encryptedCompressedMessage);
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * PGP decryption for confidentiality
     * @param encrypted The shared key and encrypted compressed message
     * @param privateKey The private key of the receiver
     * @return the decrypted message
     */
    public static byte[] PGPConfidentialityDecrypt(byte[] encrypted, Key privateKey) {
        try {
            //get the two parts of the message:
            byte[] sharedKeyEncrypted = getPartFromArray(encrypted,0,128);
            byte[] encryptedMessageOnly = getPartFromArray(encrypted,128,encrypted.length);
            //get shared key
            System.out.println("Decrypting shared key with receiver's private key");
            String decryptedSharedKeyString = decryptWithAsymmetricKey(sharedKeyEncrypted,privateKey);
            System.out.println("Extracted shared key: " + decryptedSharedKeyString);
            byte[] keyAsBytes = Base64.getDecoder().decode(decryptedSharedKeyString);
            SecretKey sharedKey = new SecretKeySpec(keyAsBytes,0,keyAsBytes.length, "AES");

            System.out.println("Decrypting content of message with extracted shared key");
            byte[] decryptedCompressedMessage = decryptWithSharedKey(encryptedMessageOnly,sharedKey);
            System.out.println("Decompressing message");
            return deCompress(decryptedCompressedMessage);
        }
        catch (Exception e) {
            e.printStackTrace();
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
        System.arraycopy(arr1, 0, finByteArr, 0, arr1.length);
        System.arraycopy(arr2, 0, finByteArr, arr1.length, arr2.length + arr1.length - arr1.length);
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
        if (to - from >= 0) System.arraycopy(arr, from, toReturn, 0, to - from);
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
        System.out.println("Encrypting with shared key");
        try{
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); //cipher instance
            SecretKeySpec keySpecification = new SecretKeySpec(sharedKey.getEncoded(), "AES"); //using AES algorithm
            byte[] IV = KeyGenerator.genIV();
            IvParameterSpec ivSpecification = new IvParameterSpec(IV);
            System.out.println("IV: " + new String(IV));
            cipher.init(Cipher.ENCRYPT_MODE, keySpecification, ivSpecification); //we want to encrypt
            byte[] cipherText = cipher.doFinal(message); //perform encryption
            String cipherTextAsString = new String(cipherText);
            System.out.println("Encrypted message with shared key: " + cipherTextAsString.substring(0,Math.min(cipherTextAsString.length(),40)));
            return concatenateArrays(IV,cipherText);
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Decrypts a message with a shared key
     * @param cipherTextWithIV Message to decrypt, with the first 16 bits being the ciphertext
     * @param sharedKey The shared key
     * @return the decrypted message
     * @throws Exception Throws exception in decryptWithSharedKey
     */
    public static byte[] decryptWithSharedKey (byte[] cipherTextWithIV, SecretKey sharedKey) throws Exception
    {
        System.out.println("Decrypting with shared key");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); //cipher instance
        SecretKeySpec keySpecification = new SecretKeySpec(sharedKey.getEncoded(), "AES"); //using AES algorithm

        byte[] IV = getPartFromArray(cipherTextWithIV, 0,16);
        byte[] toDecrypt = getPartFromArray(cipherTextWithIV,16, cipherTextWithIV.length);
        IvParameterSpec ivSpecification = new IvParameterSpec(IV);

        cipher.init(Cipher.DECRYPT_MODE, keySpecification, ivSpecification); //we want to decrypt
        byte[] decrypted = cipher.doFinal(toDecrypt); //decrypt the message
        String decryptedString = new String (decrypted);
        System.out.println("Decrypted with shared key: " + decryptedString.substring(0,Math.min(decryptedString.length(),40)));

        return decrypted;
    }


    /**
     * Encrypts with either sender's private key, or receiver's public key - depending on whether encrypt for authentication or for confidentiality
     * @param message Message to encrypt
     * @param asymmetricKey Key to encrypt with
     * @return Encrypted message
     */
    public static byte[] encryptWithAsymmetricKey(String message, Key asymmetricKey){
        System.out.println("Encrypting with asymmetric key");
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); //RSA cipher object
            cipher.init(Cipher.ENCRYPT_MODE, asymmetricKey); //encrypting mode
            byte[] cipherText = cipher.doFinal(message.getBytes()); //encrypt
            String cipherTextAsString = new String(cipherText);
            System.out.println("Encrypted message with asymmetric key: " + cipherTextAsString.substring(0,Math.min(cipherTextAsString.length(),40)));

            return cipherText;
        }
        catch (Exception e) {
            e.printStackTrace();
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
        System.out.println("Decrypting with asymmetric key");
        try {
            byte[] dectyptedText; // decrypt the text using the private key
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, asymmetricKey);
            dectyptedText = cipher.doFinal(cipherText);
            String decryptedString = new String (dectyptedText);
            System.out.println("Decrypted message with asymmetric key: " + decryptedString.substring(0,Math.min(decryptedString.length(),40)));
            return decryptedString;
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return null; //if failed
    }



    /**
     * Hashing algorithm used to hash a message.
     * @param message message to hash
     * @return hashed message in hexadecimal
     * @throws NoSuchAlgorithmException No such algorithm in hashString
     */
    public static String hashString(byte[] message) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] hash = messageDigest.digest(message); //ISO or UTF
        String hashedMessage = new String(Hex.encode(hash));
        System.out.println("Hash: " + hashedMessage.substring(0,Math.min(hashedMessage.length(),40)));
        return  hashedMessage;
    }

    /**
     * Compress a given message
     * @param message Message to compress
     * @return A compressed version of the message
     * @throws IOException IOException in compress
     */
    public static byte[] compress(byte[] message) throws IOException { //assuming message is not null
        //set up streams
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        GZIPOutputStream gzip = new GZIPOutputStream(out);
        //create compressed version
        gzip.write(message); //write the message to the output stream
        gzip.close();
        byte[] compressed = out.toByteArray();
        String compressedAsString = new String(compressed);
        System.out.println("Compressed: " + compressedAsString.substring(0,Math.min(compressedAsString.length(),40)));
        return compressed;
    }

    /**
     * Decompress a given message
     * @param compressed Compressed message
     * @return Decompressed version of the message
     * @throws IOException IOExpection in decompress
     */
    public static byte[] deCompress (byte[] compressed) throws IOException {
        //set up stream and reader
        GZIPInputStream gzipInputStream = new GZIPInputStream(new ByteArrayInputStream(compressed));
        byte[] decompressed = gzipInputStream.readAllBytes();
        String decompressedAsString = new String(decompressed);
        System.out.println("Decompressed: " + decompressedAsString.substring(0,Math.min(decompressedAsString.length(),40)));
        return decompressed;
    }





}