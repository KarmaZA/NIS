import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import javax.crypto.spec.SecretKeySpec;

/** This function will take in two file names as input and save the keys
 to those files.
 */
class KeyGenerator{

    public static Key[] generateKeyPair(){
        try {
            Security.addProvider(new BouncyCastleProvider());
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA","BC");

            generator.initialize(1024); //KeySize and fixed rand

            KeyPair keys = generator.generateKeyPair();
            Key pubKey = keys.getPublic();
            Key privateKey = keys.getPrivate();

            System.out.println("publicKey : " +  Base64.getEncoder().encodeToString(pubKey.getEncoded()));
            System.out.println("privateKey : " + Base64.getEncoder().encodeToString(privateKey.getEncoded()));
            System.out.println();

            Key[] toReturn= new Key[2];
            toReturn[0] = pubKey;
            toReturn[1] = privateKey;
            return toReturn;
        } catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Public key generator that reads the public.txt file of the CA public key and turns it into a key
     * @return The public key of the CA
     * @throws Exception File does not exist or null pointer
     */
    public static Key getCAPublicKey(String pubKey) throws Exception {
        byte [] cert = Base64.getDecoder().decode(pubKey);
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(cert);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
        return keyFactory.generatePublic(publicKeySpec);
    }

    /**
     * Generates an initialization vector
     * @return IV byte[]
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

        System.out.println("Generated sharedKey : " + Base64.getEncoder().encodeToString(sharedKey.getEncoded()));
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
}