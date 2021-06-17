import javax.crypto.SecretKey;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.util.Hashtable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

class Bob {
	private static ServerSocket serverSocket;
	//private static final String IP = "localhost";

	//Preset master key with Bob
	private static final SecretKey masterBob = null;

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
			Socket socket = serverSocket.accept();

			//RequestHandler requestHandler = new RequestHandler(socket);
			//requestHandler.start();
			try {
				System.out.println("Received a connection");

				// Get input and output streams
				BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
				PrintWriter out = new PrintWriter(socket.getOutputStream());
				//Step 1 and 2
				String line = in.readLine();
				System.out.println("The message from Alice is" + line);
				//Bob's reply
				//Generating a nonce of length 32 from the method in secure Random
				line = KeyGenerator.nonceGenerator(32);
				out.write(line);
				out.println(line);
				out.flush();

				//Step 5 and 6
				line = in.readLine();
				System.out.println("The message from Alice is" + line);
				//Bob's reply
				out.write("Hi Alice I'm Bob. Don't we need to authenticate to talk");
				out.flush();

				ExecutorService pool = Executors.newFixedThreadPool(20);
				pool.execute(new Handler(socket));
				// server socket continuosly listens for client connections
				while (true) {
					// when a client connects to server socket, the new socket is run in a seperate thread
					pool.execute(new Handler(serverSocket.accept()));
				}

				// Close our connection
				//in.close();
				//out.close();
				//socket.close();

				//System.out.println( "Connection closed" );
			} catch (Exception e) {
				e.printStackTrace();
			}
		} catch (IOException e) {
			System.out.println("Bob's bobbing did not bob up anything");
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
		//Put here for an error fix later
		final private static String password = "1234";

		private Socket socket;

		Handler(Socket socket) {
			this.socket = socket;
		}

		@Override
		public void run() {

			// client connection successful
			System.out.println("Connected: " + socket);

			try {
				// input and output streams to read and write from client
				DataInputStream in = new DataInputStream(socket.getInputStream());
				DataOutputStream out = new DataOutputStream(socket.getOutputStream());

				// initialise client HEADER that will be received
				String clientHeaderLine;

				// while() loop to keep checking for client commands received
				// >> HEADER received from client (this is the command that the client wants to perform)
				while ((clientHeaderLine = in.readUTF()) != null) { //this works
					// System.out.println(clientHeaderLine);
					String[] clientHeader = clientHeaderLine.split(",");
					System.out.println(clientHeaderLine);
					// check authentication before proceeding
					if (clientHeader[0].equals("CMD") && clientHeader[1].equals("START")) {

						if (clientHeader[2].equals(password)) {
							System.out.println("Password Correct: " + socket);
							out.writeUTF("CMD,null,null,null,success");
						} else {
							System.out.println("Password Incorrect: " + socket);
							out.writeUTF("CMD,null,null,null,fail");
						}
					}

					// QUIT or CTR
					if (clientHeader[0].equals("CMD") && clientHeader[1].equals("quit")) {
						System.out.println("Ending socket connection...");
						// break out of while() loop so that the finally() block can be run
						break;
					} else if (clientHeader[0].equals("Auth") && clientHeader[1].equals("I")) {
						// System.out.println("here");
						try {
							int bytesRead;

							// record filename and password from  client HEADER
							String fileName = clientHeader[2];
							// System.out.print(fileName);
							//String password = clientHeader[2];

							// if(fileNames.containsKey(fileName)){ //already exists. cannot upload
							//     System.out.println("File "+fileName+" already exists");
							//     out.writeUTF("CTR,null,null,null,fileexists");
							// }
							//if (!fileNames.containsKey(fileName)){ //file name not exist{
							//out.writeUTF("CTR,null,null,null,success"); //send signal to uplaod
							// outputstream to write file uploaded from client onto server PC
							OutputStream output = new FileOutputStream("output/" + fileName);
							// >> HEADER received from client containing length of byte array to upload
							long size = in.readLong();
							long capSize = in.readLong();
							// System.out.println(capSize);
							byte[] buffer = new byte[(int) size];
							while (size > 0 && (bytesRead = in.read(buffer, 0, (int) Math.min(buffer.length, size))) != -1) {
								output.write(buffer, 0, bytesRead);
								size -= bytesRead;
							}
							output.close();
							byte[] capBuff = new byte[(int) capSize];
							in.read(capBuff, 0, (int) capSize);
							// byte[] cap = in.readAllBytes();
							String Caption = new String(capBuff);
							System.out.println("File received: " + fileName);
							System.out.println("Image Caption: " + Caption);
							out.writeUTF("CTR,null,null,null,success"); //send signal to uplaod
							// }
						} catch (IOException ex) {
							System.out.println("Could not upload file...");
							out.writeUTF("CTR,null,null,null,failed");
						}
					} else if (clientHeader[0].equals("Auth") && clientHeader[1].equals("M")) {
						System.out.println("Message from Alice:");
						System.out.println(in.readUTF());
						//System.out.println("\n");
						// break out of while() loop so that the finally() block can be run
					}
				}
			} catch (Exception e) {
				System.out.println(e);
				System.out.println("Error:" + socket);
			} finally {
				try {
					socket.close();
					System.out.println("Closed: " + socket);
				} catch (IOException e) {
					System.out.println(e);
				}
			}
		}


		/**
		 * checks if string is a digit
		 *
		 * @param strNum
		 * @return
		 */
		public static boolean isInteger(String strNum) {
			if (strNum == null) {
				return false;
			}
			try {
				int num = Integer.parseInt(strNum);
			} catch (NumberFormatException nfe) {
				return false;
			}
			return true;
		}

	}
}
/* Commenting this out to test something will re implement later or use Piero's version
/**
 *
 * /
class RequestHandler extends Thread
{
	/**
	 *
	 * /
	private Socket socket;
	RequestHandler( Socket socket )
	{
		this.socket = socket;
	}

	/**
	 *
	 * /
	@Override
	public void run()
	{
		try
		{
			System.out.println( "Received a connection" );

			// Get input and output streams
			BufferedReader in = new BufferedReader( new InputStreamReader( socket.getInputStream() ) );
			PrintWriter out = new PrintWriter( socket.getOutputStream() );
			//Step 1 and 2
			String line = in.readLine();
			System.out.println("The message from Alice is" + line);
			//Bob's reply
			line = "Hi Alice, I'm Bob. Don't we need to authenticate to talk";
			out.write(line);
			out.println(line);
			out.flush();

			//Step 5 and 6
			line = in.readLine();
			System.out.println("The message from Alice is" + line);
			//Bob's reply
			out.write("Hi Alice I'm Bob. Don't we need to authenticate to talk");
			out.flush();
			// Close our connection
			in.close();
			out.close();
			socket.close();

			System.out.println( "Connection closed" );
		}
		catch( Exception e )
		{
			e.printStackTrace();
		}
	}
}*/