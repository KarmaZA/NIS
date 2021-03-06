import javax.crypto.SecretKey;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
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
	private final static Scanner scanner = new Scanner(System.in);
	private static final int portNumber = 45554;
	private final static String username = "Bob";

	private static String certificateExpiryDate;

	private static SecretKey masterBob = null;
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
			Key[] keypair = KeyGenerator.generateKeyPair();
			assert keypair!=null;
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
			// server socket continuously listens for client connections
			while (true) {
				// when a client connects to server socket, the new socket is run in a separate thread
				pool.execute(new Handler(serverSocket.accept()));
				System.out.println("new socket");
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Method to generate a certificate from the Authentication server
	 * @param certificate the public key
	 * @return Signed Hash of the public key
	 */
	private static byte[] signCertificate(byte[] certificate){
		try {
			System.out.println("Generating a signed certificate.");
			Socket authServerSocket = new Socket("localhost", 45555);
			DataOutputStream outAuthServ = new DataOutputStream(authServerSocket.getOutputStream());
			DataInputStream inAuthServ = new DataInputStream(authServerSocket.getInputStream());

			System.out.println("Connected to CA.");
			certificate = Objects.requireNonNull(SecurityFunctions.encryptWithSharedKey(certificate,masterBob));

			outAuthServ.writeUTF("SIGN," + certificate.length +",Bob,null,null");
			System.out.println("Sent the certificate to the Authentication Server");
			outAuthServ.write(certificate);

			String certify = inAuthServ.readUTF();
			String[] certifyArray = certify.split(",");

			certificate = inAuthServ.readNBytes(Integer.parseInt(certifyArray[2]));

			if (certifyArray[0].equals("SIGNED")){
				certificateExpiryDate = certifyArray[3];
				System.out.println("Signed certificate has been returned");
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

	private static void getCAPublicKey() throws Exception {
		Socket authServerSocket = new Socket("localhost", 45555);
		DataOutputStream out = new DataOutputStream(authServerSocket.getOutputStream());
		DataInputStream in = new DataInputStream(authServerSocket.getInputStream());

		out.writeUTF("REQKEY,null,null,null,null");
		int len = (int) in.readLong();
		byte[] pubKey = in.readNBytes(len);
		publicKeyCA = KeyGenerator.getCAPublicKey(new String(pubKey));
	}



	private static class Handler implements Runnable {

		private final Socket socket;
		Handler(Socket socket) {
			this.socket = socket;
		}

		private static boolean getPublicKey(byte[] cert, byte[] hashString) throws InvalidKeySpecException, NoSuchProviderException, NoSuchAlgorithmException {
			Calendar calendar = Calendar.getInstance();
			String dayOfTheYear = calendar.get(Calendar.DAY_OF_YEAR) + "";
			if(Integer.parseInt(dayOfTheYear) >= Integer.parseInt(certificateExpiryDate)){
				System.out.println("Certificate Expired");
				return false;
			}
			System.out.println("Certificate has not expired");

			byte[] hashToDecrypt = writeThread.joinByteArray(cert, certificateExpiryDate.getBytes());
			String checkHash = SecurityFunctions.hashString(hashToDecrypt);
			String decryptedSignature = SecurityFunctions.decryptWithAsymmetricKey(hashString, publicKeyCA);
			System.out.println("The hash has been decrypted");

			assert hashString!=null;
			if(checkHash.equals(decryptedSignature)){
				System.out.println("Signature of CA validated");
				cert = Base64.getDecoder().decode(cert);
				EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(cert);
				KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
				AlicePublicKey = keyFactory.generatePublic(publicKeySpec);
				System.out.println("Public key retrieved");
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
				Bob.getCAPublicKey();
				DataInputStream in = new DataInputStream(socket.getInputStream());
				DataOutputStream out = new DataOutputStream(socket.getOutputStream());

				String requestHeader = in.readUTF();
				System.out.println(requestHeader);
				String[] requestHeaderArray = requestHeader.split(",");
				byte[] certificate;
				if(requestHeaderArray[0].equals("CMD") && requestHeaderArray[1].equals("START") && requestHeaderArray[2].equals("REQCOM")){
					System.out.println("Communication request received from " + requestHeaderArray[3]);

					certificate = Base64.getEncoder().encode(publicKey.getEncoded());
					System.out.println("Requesting certificate");
					byte[] signedCertificate = Bob.signCertificate(certificate);


					System.out.println("The certificate has been signed");
					assert certificate != null;

					assert signedCertificate != null;
					out.writeUTF("CMD," + certificateExpiryDate + "," + certificate.length + "," + username + "," + signedCertificate.length);
					out.write(certificate);
					out.write(signedCertificate);
					System.out.println("Certificate has been sent");
				}
				requestHeader = in.readUTF();
				requestHeaderArray = requestHeader.split(",");

				certificate = in.readNBytes(Integer.parseInt(requestHeaderArray[2]));
				byte[] certSignature = in.readNBytes(Integer.parseInt(requestHeaderArray[3]));
				System.out.println("Certificate Received");
				System.out.println("Extracting Public Key");

				if(!getPublicKey(certificate, certSignature)){
					System.out.println("Invalid certificate");
					System.exit(1);
				}
				System.out.println("Authentication Succeeded");
				/* ************START MESSAGING ******************/
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