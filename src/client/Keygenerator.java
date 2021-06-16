import java.io.BufferedWriter;
import java.io.FileWriter;
import java.security.*;
import java.util.Base64;
import org.bouncycastle.*;  
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.*;
import org.bouncycastle.*;


/*TODO
        Get bouncycastle to work to test properly
        get correct version of .getInstance() as per project specs
        Implement Base64 in key storage
        Find a better way to store and deal with the keys.
 */

	/* This function will take in two file names as input and save the keys
	to those files.
	 */
class KeyGenerator{
    public static void main(String[] args) throws NoSuchAlgorithmException {
        generateKeyPair("public.txt","private.txt");
    }

        /**
         *
         * @param publicFile name of the file for the private key.
         * @param privateFile name of the file for the public key.
         * @throws NoSuchAlgorithmException
         */
    private static void generateKeyPair(String publicFile, String privateFile) throws NoSuchAlgorithmException {
        try {
            // fix line below too
            Security.addProvider(new BouncyCastleProvider());
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");//,"BC");
            //BASE64Encoder

            SecureRandom rand = secureRandomGen();
            generator.initialize(1024, rand); //Keysize and fixed rand

            KeyPair keys = generator.generateKeyPair();
            Key pubKey = keys.getPublic();
            Key privKey = keys.getPrivate();


            System.out.println("publicKey : " + Base64.getEncoder().encodeToString(pubKey.getEncoded()));
            System.out.println("privateKey : " +Base64.getEncoder().encodeToString(privKey.getEncoded()));

            //write to files
            BufferedWriter BWout = new BufferedWriter(new FileWriter(publicFile));
            BWout.write("" + Base64.getEncoder().encodeToString(pubKey.getEncoded()));
            BWout.close();

            BWout = new BufferedWriter(new FileWriter(privateFile));
            BWout.write("" + Base64.getEncoder().encodeToString(privKey.getEncoded()));
            BWout.close();


        } catch (Exception e){
            e.printStackTrace();
        }

    }

    private static SecureRandom secureRandomGen(){ return new FixedRand();}

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