import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
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

	private final static String username = "Bob";

	//Public private key pair
	public static Key publicKey;
	private static Key privateKey;
	private static Key publicKeyCA;
	private static Key AlicePublicKey;

	/**
	 * @param args String array to take input into the main method
	 */
	public static void main(String[] args) {
		masterBob = KeyGenerator.genMasterKeyFromString("055WVjVBB95Yaw6ZhRAWug==");
		try {
			publicKeyCA = KeyGenerator.getCAPublicKey();
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

	private static byte[] signCertificate(byte[] certificate){
		try {

			System.out.println("Generating a signed certificate.    " + new String(certificate));
			Socket authServerSocket = new Socket("localhost", 45555);
			DataOutputStream outAuthServ = new DataOutputStream(authServerSocket.getOutputStream());
			DataInputStream inAuthServ = new DataInputStream(authServerSocket.getInputStream());
			System.out.println("Connected to CA.");

			certificate = Objects.requireNonNull(SecurityFunctions.encryptWithSharedKey(certificate,masterBob));

			outAuthServ.writeUTF("SIGN," + certificate.length +",Bob,null,null");
			outAuthServ.write(certificate);
			String certify = inAuthServ.readUTF();
			String[] certifyArray = certify.split(",");
			//Can Delete
			certificate = inAuthServ.readNBytes(Integer.parseInt(certifyArray[2]));
			//certificate = SecurityFunctions.decryptWithAsymmetricKey(certificate,publicKeyCA).getBytes();

			if (certifyArray[0].equals("SIGNED")){
				return certificate;
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

		private static boolean getPublicKey(byte[] cert, byte[] hashString) throws InvalidKeySpecException, NoSuchProviderException, NoSuchAlgorithmException {
			//Use CA public key
			//cert = SecurityFunctions.decryptWithAsymmetricKey(cert.getBytes(),publicKeyCA);
			//cert = SecurityFunctions.decryptWithAsymmetricKey(cert,publicKeyCA).getBytes();
			System.out.println("Hash string");
			System.out.println(hashString.length);
			String checkHash = SecurityFunctions.hashString(cert);
			String decryptedSignature = SecurityFunctions.decryptWithAsymmetricKey(hashString, publicKeyCA);
			System.out.println("The hashes are");
			System.out.println(checkHash);
			System.out.println(decryptedSignature);
			assert hashString!=null;
			if(checkHash.equals(decryptedSignature)){
				System.out.println("It works");
				cert = Base64.getDecoder().decode(cert);
				EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(cert);
				KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
				AlicePublicKey = keyFactory.generatePublic(publicKeySpec);
				return true;
			} else {
				return false;
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
				publicKeyCA = KeyGenerator.getCAPublicKey();
				DataInputStream in = new DataInputStream(socket.getInputStream());
				DataOutputStream out = new DataOutputStream(socket.getOutputStream());

				String requestHeader = in.readUTF();
				System.out.println(requestHeader);
				String[] requestHeaderArray = requestHeader.split(",");
				String nonce = KeyGenerator.nonceGenerator(16);
				byte[] certificate;
				if(requestHeaderArray[0].equals("CMD") && requestHeaderArray[1].equals("START") && requestHeaderArray[2].equals("REQCOM")){
					//Communication request received send back a non
					System.out.println("Communication request received from " + requestHeaderArray[3]);

					//generates a certificate from the "CA" (AuthServer)
					certificate = Base64.getEncoder().encode(publicKey.getEncoded());
					//System.out.println();
					byte[] signedCertificate = Bob.signCertificate(certificate);


					System.out.println("The certificate has been signed");
					assert certificate != null;

					assert signedCertificate != null;
					out.writeUTF("CMD," + nonce + "," + certificate.length + "," + username + "," + signedCertificate.length);
					out.write(certificate);
					out.write(signedCertificate);
					System.out.println("Certificate has been sent");
				}
				requestHeader = in.readUTF();
				requestHeaderArray = requestHeader.split(",");

				certificate = in.readNBytes(Integer.parseInt(requestHeaderArray[2]));
				byte[] certSignature = in.readNBytes(Integer.parseInt(requestHeaderArray[3]));

				System.out.println("Extracting Public Key");
				System.out.println("Certificate Received");

				if(!getPublicKey(certificate, certSignature)){
					System.out.println("Invalid certificate");
					System.exit(1);
				}

				// initialise client HEADER that will be received
				String clientAuthHeaderLine;
				while ((clientAuthHeaderLine = in.readUTF()) != null) { //read in from Alice
					System.out.println("here");
					String[] clientAuthHeader = clientAuthHeaderLine.split(";");
					// check authentication before proceeding
					if(clientAuthHeader[0].equals("CMD") && clientAuthHeader[1].equals("START")){

						if(clientAuthHeader[2].equals(Bob.password)){
							System.out.println("Password Correct: " + socket);

							//extract Alice's public key
							byte [] publicKeyBytes = Base64.getDecoder().decode(clientAuthHeader[3].getBytes());
							EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
							KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
							Key AlicePublicKey1= keyFactory.generatePublic(publicKeySpec);
							if(AlicePublicKey1.equals(AlicePublicKey))System.out.println("True");
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
				readThread read = new readThread("Alice", socket, in, out, Bob.privateKey, AlicePublicKey);
				writeThread write = new writeThread("Alice", scanner, socket, in, out, Bob.privateKey, AlicePublicKey );

				read.start();
				write.start();

			} catch (Exception e) {
				System.out.println("Bye Bob");
			}
		}
	}
}