import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

class Bob {
	private static ServerSocket serverSocket;
	//private static final String IP = "localhost";
	private static Scanner scanner = new Scanner(System.in);

	//Preset master key with Bob
	private static SecretKey masterBob = null;

	// server password (client must authenticate before accessing server)
	final private static String password = "1234";

	// hash table to store all file names and passwords
	private static Hashtable<String, String> fileNames = new Hashtable<String, String>();

	//key is name, the other thing is the password
	private static final int portNumber = 45554;

	//Public private key pair
	public static Key publicKey;
	private static Key privateKey;
	private static SecretKey communicationSessionKey;
	private static Key AlicePublicKey;

	/**
	 * @param args String array to take input into the main method
	 */
	public static void main(String[] args) {
		masterBob = KeyGenerator.genMasterKeyFromString("055WVjVBB95Yaw6ZhRAWug==");
		try {
			Key[] keypair = KeyGenerator.generateKeyPair();
			publicKey = keypair[0];
			privateKey = keypair[1];
		} catch (Exception e) {
			System.out.println("Could not generate key pair");
			e.printStackTrace();
		}
		startServer();
		System.out.println("Bob is bobbing");


		try {
			ExecutorService pool = Executors.newFixedThreadPool(20);
			// server socket continuosly listens for client connections
			while (true) {
				// when a client connects to server socket, the new socket is run in a seperate thread
				pool.execute(new Handler(serverSocket.accept()));
				System.out.println("new socket");
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	private static String signCertificate(String certificate){
		try {
			System.out.println("Generating a signed certificate.");
			Socket authServerSocket = new Socket("localhost", 45555);
			DataOutputStream outAuthServ = new DataOutputStream(authServerSocket.getOutputStream());
			DataInputStream inAuthServ = new DataInputStream(authServerSocket.getInputStream());
			System.out.println("Connected to CA.");

			outAuthServ.writeUTF("SIGN," + certificate +",bob,null,null");
			String certify = inAuthServ.readUTF();
			String[] certifyArray = certify.split(",");

			if (certifyArray[0].equals("SIGNED")){
				/*System.out.println("here");
				String toReturn = certifyArray[1];
				System.out.println(toReturn);
				Key publicKey = KeyGenerator.getCAPublicKey();
				System.out.println("Got pub key");
				toReturn = Objects.requireNonNull(SecurityFunctions.decryptWithAsymmetricKey(toReturn.getBytes(), publicKey));
				System.out.println(toReturn);
	//Objects.requireNonNull(SecurityFunctions.decryptWithAsymmetricKey(
				//						certifyArray[1].getBytes(StandardCharsets.UTF_8),KeyGenerator.getCAPublicKey()))
				return toReturn;*/ return certifyArray[1];
			}
		} catch (Exception e) {
			System.out.println("I have nothing to connect to :'(");
		}
		return null;

	}

	/**
	 * starts the ServerSocket in an try catch block in case of an IO Exception
	 */
	private static void startServer() {
		try {
			serverSocket = new ServerSocket(portNumber);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}



	private static class Handler implements Runnable {

		private final Socket socket;
		Handler(Socket socket) {
			this.socket = socket;
		}

		/**
		 * Decodes the encoded byte[] from Authentication server sent via Alice encoded with Bob's master key
		 * that is shared with the server. Returns a session key if authenticated else null
		 * @param encoded encoded string with Bob's master key
		 * @param nonce nonce that Bob sent to Alice
		 * @return session key if valid else null
		 * @throws Exception assumes failed authentication returns null
		 */
		private static byte[] verifyConnection(byte[] encoded, String nonce){
			//This is working without encryption/decryption
			//The right amount of data is getting here4
			try {
				System.out.println("in verify Connection");
				encoded = (SecurityFunctions.decryptWithSharedKey(encoded,masterBob,false));
				System.out.println(new String(encoded));
				byte[] sessionKey = Arrays.copyOfRange(encoded, 0, encoded.length - 23);

				System.out.println("Session key: " + new String(sessionKey));
				String aliceCheck = new String(Arrays.copyOfRange(encoded, encoded.length - 23, encoded.length-16));
				System.out.println(aliceCheck);
				String nonceCheck = new String(Arrays.copyOfRange(encoded, encoded.length - 16, encoded.length));
				System.out.println(nonce);

				if (nonce.equals(nonceCheck) && aliceCheck.equals("|Alice|")) {
					return sessionKey;
				} else {
					return null;
				}
			} catch (Exception e){
				//Any form of exception constitutes authentication failure
				System.out.println("Exception thrown. Disconnect for safety.");
				e.printStackTrace();
				return null;
			}
		}

		/**
		 * Run method for the thread. undergoes the authentication then if successful spawns threads to read and
		 * write data for Bob to and from Alice
		 */
		@Override
		public void run() {
			// client connection successful
			System.out.println("Verifying Alice on: " + socket);
			try {
//				DataInputStream in = new DataInputStream(socket.getInputStream());
//				DataOutputStream out = new DataOutputStream(socket.getOutputStream());
//				//Step 1 and 2
//				String aliceAuthHeaderLine = in.readUTF();
//				System.out.println(aliceAuthHeaderLine);
//				String[] AliceHeaderLine = aliceAuthHeaderLine.split(",");
//				String nonce = KeyGenerator.nonceGenerator(16);
//				if(AliceHeaderLine[0].equals("CMD") && AliceHeaderLine[1].equals("START") && AliceHeaderLine[2].equals("REQCOM")){
//					//Communication request received send back a non
//					System.out.println("Communication request received");
//					//generates a certificate from the "CA" (AuthServer)
//					String certificate = Bob.signCertificate("bob");
//					System.out.println(certificate);
//					//String certificate = "bob";
//					System.out.println("The certificate has been signed");
//					out.writeUTF("CMD," + nonce + "," + certificate + ",null,null");
//				}
//
//				//Step 5 and 6
//				long bufferSize = in.readLong();
//				byte[] buffer = in.readNBytes((int)bufferSize);
//				System.out.println("The message from Alice is" + buffer.toString());
//
//				byte[] sessionKey = verifyConnection(buffer, nonce);
//				if(sessionKey == null){
//					System.out.println("Authentication Failure");
//					System.out.println("Program Exiting to avoid malicious connection");
//					System.exit(1);
//				}
				//TODO Is this the correct way to create a Session key with what we have?
//				Bob.communicationSessionKey = new SecretKeySpec(sessionKey, 0, sessionKey.length, "AES");
				// scanner used for all client input

				// input and output streams to read and write from client

				// initialise client HEADER that will be received


			DataInputStream in = new DataInputStream(socket.getInputStream());
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
				String clientAuthHeaderLine;
				while ((clientAuthHeaderLine = in.readUTF()) != null) { //read in from Alice
					String[] clientAuthHeader = clientAuthHeaderLine.split(";");
					// check authentication before proceeding
					if(clientAuthHeader[0].equals("CMD") && clientAuthHeader[1].equals("START")){

						if(clientAuthHeader[2].equals(Bob.password)){
							System.out.println("Password Correct: " + socket);

							//extract Alice's public key
							byte [] publicKeyBytes = Base64.getDecoder().decode(clientAuthHeader[3].getBytes());
							EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
							KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
							AlicePublicKey= keyFactory.generatePublic(publicKeySpec);

							//send Bob's public key to Alice
							String BobPublicKeyString =  new String(Base64.getEncoder().encode(publicKey.getEncoded()));
							out.writeUTF("CMD;"+BobPublicKeyString+";null;null;success");
							Alice.done = false;
							break;
						}
						else{
							System.out.println("Password Incorrect: " + socket);
							out.writeUTF("CMD;null;null;null;fail");
						}
					}
				}

				//threads for sending and receiving messages/images
				readThread read = new readThread("Alice", socket, in, out, communicationSessionKey, Bob.privateKey, AlicePublicKey);
				writeThread write = new writeThread("Alice", scanner, socket, in, out, communicationSessionKey, Bob.privateKey, AlicePublicKey );

				read.start();
				write.start();

			} catch (Exception e) {
				System.out.println("Bye Bob");
			}
		}
	}
}