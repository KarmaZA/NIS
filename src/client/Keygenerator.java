import java.io.BufferedWriter;
import java.io.FileWriter;
import java.security.*;
import java.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.*;
import org.bouncycastle.*;

import javax.crypto.SecretKey;
//package com.javainterviewpoint;

import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import javax.crypto.spec.SecretKeySpec;


/** This function will take in two file names as input and save the keys
to those files.
 */
class KeyGenerator{
    public static void main(String[] args) throws NoSuchAlgorithmException {
//        generateKeyPair("public.txt","private.txt");
    }
    public static String nonceGenerator(int size){
        SecureRandom secureRandom = new SecureRandom();
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < size; i++) {
            stringBuilder.append(secureRandom.nextInt(10));
        }
        String randomNumber = stringBuilder.toString();
        return randomNumber;
    }


    //private static Key[] generateKeyPair(String publicFile, String privateFile) throws NoSuchAlgorithmException {
    public static Key[] generateKeyPair() throws NoSuchAlgorithmException {
        try {
            // fix line below too
            Security.addProvider(new BouncyCastleProvider());
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA","BC");
            //BASE64Encoder
            SecureRandom rand = secureRandomGen();
//            generator.initialize(1024, rand); //Keysize and fixed rand
            generator.initialize(1024); //Keysize and fixed rand

            KeyPair keys = generator.generateKeyPair();
            Key pubKey = keys.getPublic();
            Key privKey = keys.getPrivate();

            System.out.println("here 4");
            System.out.println("publicKey : " + Base64.getEncoder().encodeToString(pubKey.getEncoded()));
            System.out.println("privateKey : " +Base64.getEncoder().encodeToString(privKey.getEncoded()));
            System.out.println();

            Key[] toReturn= new Key[2];
            toReturn[0] = pubKey;
            toReturn[1] = privKey;
            return toReturn;


//            //write to files
//            BufferedWriter BWout = new BufferedWriter(new FileWriter(publicFile));
//            BWout.write("" + Base64.getEncoder().encodeToString(pubKey.getEncoded()));
//            BWout.close();
//
//            BWout = new BufferedWriter(new FileWriter(privateFile));
//            BWout.write("" + Base64.getEncoder().encodeToString(privKey.getEncoded()));
//            BWout.close();


        } catch (Exception e){
            e.printStackTrace();
        }
        return null; //if it didnt work

    }

    /**
     *
     * @return
     */
    public static byte[] genIV(){
        // Generating IV.
        byte[] IV = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(IV);
        return IV;
    }

    /**
     * Generates a shared key.
     * @return a SecretKey that is a usable shared key
     */
    public static SecretKey genSharedKey(){

        // SecureRandom is expensive to initialize (takes several milliseconds) –
        // consider keeping the instance around if you are generating many keys.
        SecureRandom random = new SecureRandom();
        byte[] keyBytes = new byte[16];
        random.nextBytes(keyBytes);
        SecretKeySpec sharedKey = new SecretKeySpec(keyBytes, "AES");

        System.out.println("sharedKey : " + Base64.getEncoder().encodeToString(sharedKey.getEncoded()));
        return sharedKey;
    }

    /**
     * This method takes in a string that should come from a Base64 encoded Key using .encodeToString(key.getEncoded())
     * @param key The string of the encoded key
     * @return the Secret Key generated from the String
     */
    public static SecretKey genMasterKeyFromString(String key){
        byte[] decodedKey = Base64.getDecoder().decode(key);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }

    /**
     *
     * @return
     */
    private static SecureRandom secureRandomGen(){ return new FixedRand();}


    /**
     *
     */
    private static class FixedRand extends SecureRandom{
        MessageDigest sha;
        byte[] state;

        /**
         * Constructor that set up the SHA encryption level and the state,
         */

        FixedRand(){
            try{
                this.sha = MessageDigest.getInstance("SHA-1"); //Placeholder please can we use better encryption
                this.state = sha.digest();
            } catch (NoSuchAlgorithmException e){
                e.printStackTrace();
            }
        }

        /**
         *
         * @param bytes
         */
        public void nextBytes(byte[] bytes){
            int offset = 0;
            sha.update(state);

            while(offset < bytes.length){
                sha.digest();

                if(bytes.length - offset > state.length){
                    System.arraycopy(state, 0, bytes, offset, state.length);
                }
                else {
                    System.arraycopy(state, 0, bytes, offset, bytes.length - offset);
                }
                offset += state.length;
                sha.update(state);
            }
        }


    }
}