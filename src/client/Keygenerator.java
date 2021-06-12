import java.io.BufferedWriter;
import java.io.FileWriter;
import java.security.*;

//A function to generate a public/private RSA key set
	/* This function will take in two file names as input and save the keys
	to those files.
	 */
public class KeyGenerator{

    private void generateKeyPair(String publicFile, String privateFile) throws NoSuchAlgorithmException {
        try {
            // fix line below too
            // Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");//,"BC);
            //BASE64Encoder

            SecureRandom rand = secureRandomGen();
            generator.initialize(1024, rand); //Keysize and fixed rand

            KeyPair keys = generator.generateKeyPair();
            Key pubKey = keys.getPublic();
            Key privKey = keys.getPrivate();

            System.out.println("publicKey : " + pubKey.getEncoded());
            System.out.println("privateKey : " +privKey.getEncoded());

            //write to files
            BufferedWriter BWout = new BufferedWriter(new FileWriter(publicFile));
            BWout.write(pubKey.getEncoded() + "");
            BWout.close();

            BWout = new BufferedWriter(new FileWriter(privateFile));
            BWout.write("" + privKey);
            BWout.close();

            // We should write these in some form of encryption like Base64. I'm doing this in a break and don't have time
            // to work it out now. I'll test this and get it running on monday
        } catch (Exception e){
            e.printStackTrace();
        }

    }

    public static SecureRandom secureRandomGen(){ return new FixedRand();}

    private static class FixedRand extends SecureRandom{
        MessageDigest sha;
        byte[] state;

        /*
        Class constructor
         */
        FixedRand(){
            try{
                this.sha = MessageDigest.getInstance("SHA-1"); //Placeholder please can we use better encryption
                this.state = sha.digest();
            } catch (NoSuchAlgorithmException e){
                e.printStackTrace();
            }
        }

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