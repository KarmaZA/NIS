import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
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
	public static Key publicKeyCA;
	private static Key AlicePublicKey;
	private final static String username = "Bob";

	/**
	 * @param args String array to take input into the main method
	 */
	public static void main(String[] args) {
		masterBob = KeyGenerator.genMasterKeyFromString("055WVjVBB95Yaw6ZhRAWug==");

		try {
			Key[] keypair = KeyGenerator.generateKeyPair();
			publicKey = keypair[0];
			privateKey = keypair[1];
			publicKeyCA = KeyGenerator.getCAPublicKey();
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
				System.out.println("Socket accepted");
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

			certificate = Objects.requireNonNull(SecurityFunctions.encryptWithSharedKey(certificate,masterBob,false));

			outAuthServ.writeUTF("SIGN," + certificate.length +",Bob,null,null");
			outAuthServ.write(certificate);
			String certify = inAuthServ.readUTF();
			String[] certifyArray = certify.split(",");

			certificate = inAuthServ.readNBytes(Integer.parseInt(certifyArray[1]));

			//TODO returns the username|publickey encrypted with CA private key
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

		private static boolean authenticateCertificate(String cert){
			//Use CA public key
			//cert = SecurityFunctions.decryptWithAsymmetricKey(cert.getBytes(),publicKeyCA);
			//Make sure decrypted says bob
			return true;
		}


		/**
		 * Run method for the thread. undergoes the authentication then if successful spawns threads to read and
		 * write data for Bob to and from Alice
		 */
		@Override
		public void run() {
			// client connection successful
			try {
				DataInputStream in = new DataInputStream(socket.getInputStream());
				DataOutputStream out = new DataOutputStream(socket.getOutputStream());

				String requestHeader = in.readUTF();
				System.out.println(requestHeader);
				String[] requestHeaderArray = requestHeader.split(",");
				String nonce = KeyGenerator.nonceGenerator(16);

				if(requestHeaderArray[0].equals("CMD") && requestHeaderArray[1].equals("START") && requestHeaderArray[2].equals("REQCOM")){
					//Communication request received send back a non
					System.out.println("Communication request received from " + requestHeaderArray[3]);

					//generates a certificate from the "CA" (AuthServer)
					byte[] certificate = Base64.getEncoder().encode(publicKey.getEncoded());
					//System.out.println();
					certificate = Bob.signCertificate(certificate);


					System.out.println("The certificate has been signed");
					assert certificate != null;

					out.writeUTF("CMD," + nonce + "," + certificate.length + "," + username + ",null");
					out.write(certificate);
					System.out.println("Certificate has been sent");
				}

				requestHeader = in.readUTF();
				requestHeaderArray = requestHeader.split(",");

				if(!authenticateCertificate(requestHeaderArray[2])){
					in.close();
					out.close();
					System.out.println("Certificate invalid or expired.\nTerminating");
					System.exit(1);
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