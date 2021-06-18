import javax.crypto.SecretKey;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Hashtable;
import java.util.Scanner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

class Bob {
	private static ServerSocket serverSocket;
	//private static final String IP = "localhost";

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

		private Socket socket;
		Handler(Socket socket) {
			this.socket = socket;
		}

		@Override
		public void run() {
			// client connection successful
			System.out.println("Verifying Alice on: " + socket);
			/******************************/
			try {// Get input and output streams
				DataInputStream in = new DataInputStream(socket.getInputStream());
				DataOutputStream out = new DataOutputStream(socket.getOutputStream());
				//Step 1 and 2
				String aliceAuthHeaderLine = in.readUTF();
				System.out.println(aliceAuthHeaderLine);
				String[] AliceHeaderLine = aliceAuthHeaderLine.split(",");
				if(AliceHeaderLine[0].equals("CMD") && AliceHeaderLine[1].equals("START") && AliceHeaderLine[2].equals("REQCOM")){
					//Communication request received send back a non
					System.out.println("Communication request received");
					out.writeUTF("CMD," + KeyGenerator.nonceGenerator(16) + ",null,null,null");
				}

				//Step 5 and 6
				System.out.println("Here");
				long bufferSize = in.readLong();
				System.out.println("Here");
				byte[] buffer = in.readNBytes((int)bufferSize);
				System.out.println("The message from Alice is");// + buffer.toString());

			/******************************/
				try {
					// scanner used for all client input
					Scanner scanner = new Scanner(System.in);
					// input and output streams to read and write from client

					// initialise client HEADER that will be received
					String clientAuthHeaderLine;
					while ((clientAuthHeaderLine = in.readUTF()) != null) { //read in from Alice
						String[] clientAuthHeader = clientAuthHeaderLine.split(",");
						// check authentication before proceeding
						if(clientAuthHeader[0].equals("CMD") && clientAuthHeader[1].equals("START")){

							if(clientAuthHeader[2].equals(Bob.password)){
								System.out.println("Password Correct: " + socket);
								out.writeUTF("CMD,null,null,null,success");
								Alice.done = false;
								break;
							}
							else{
								System.out.println("Password Incorrect: " + socket);
								out.writeUTF("CMD,null,null,null,fail");
							}
						}
					}

					//threads for sending and receiving messages/images
					readThread read = new readThread("Alice", socket, in, out);
					writeThread write = new writeThread("Alice", scanner, socket, in, out);
					read.start();
					write.start();

				} catch (Exception e) {
					System.out.println("Bye Bob");
				}
			} catch (Exception e){
				System.out.println("Jonno's code is the problem");
				//Delete this try catch block later
			}
		}
	}
}