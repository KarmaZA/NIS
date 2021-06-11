import java.io.IOException;
import java.net.Socket;
import java.util.Scanner;
import java.security.*;
import sun.misc.BASE64Encoder;



public class Client {
	private static String userName = "Jonno";
	private String serverHost;
	private int serverPort = 4444;
	private Scanner userInputScanner;

	public static void main(String[] args) {
		Socket socket = null;
		int portNumber = 4444; //We Make sure it's connecting to the port with the listener on it
		try {
			socket = new Socket("localhost", portNumber);
			Thread.sleep(1000);
			Thread server = new Thread(new ServerThread(socket, userName));
			server.start();
		} catch (IOException e) {
			System.err.println("Client.java;;No connection made on port: " + portNumber);
			e.printStackTrace();
		} catch (InterruptedException e) {
			System.err.println("Client.java;;No connection made on port: " + portNumber);
			e.printStackTrace();
		}
	}
};
	//A function to generate a public/private RSA key set
	/* This function will take in two file names as input and save the keys
	to those files.
	https://www.mysamplecode.com/2011/08/java-generate-rsa-key-pair-using-bouncy.html
	 */
public class GenerateRSAKeys{

	private void generateKeyPair(String publicFile, String privateFile) throws NoSuchAlgorithmException {
		try {
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");//,"BC);
			//BASE64Encoder

			SecureRandom rand = secureRandomGen();
			generator.initialize(1024, rand); //Keysize and fixed rand

			KeyPair keys = generator.generateKeyPair();
			Key pubKey = keys.getPublic();
			Key privKey = keys.getPrivate();

			System.out.println("publicKey : " + pubKey.getEncoded());
			System.out.println("privateKey : " +privKey.getEncoded());

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

				if(bytes.length - off > state.length){
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













