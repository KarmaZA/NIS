

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

class Bob{
	private static ServerSocket serverSocket;
	//private static final String IP = "localhost";
	private static final int portNumber = 45554;
	public static Key publicKey;
	private static Key privateKey;

	/**
	 *
	 * @param args String array to take input into the main method
	 */
	public static void main(String[] args){
		try {
			Key[] keypair = KeyGenerator.generateKeyPair();
			publicKey = keypair[0];
			privateKey = keypair[1];
		} catch (NoSuchAlgorithmException e){
			System.out.println("Could not generate key pair");
			e.printStackTrace();
		}
		startServer();
		System.out.println("Bob is bobbing");
		try {
			Socket socket = serverSocket.accept();

			RequestHandler requestHandler = new RequestHandler(socket);
			requestHandler.start();
		} catch (IOException e){
			System.out.println("Bob's bobbing did not bob up anything");
			e.printStackTrace();
		}*/
	}

	/**
	 * starts the ServerSocket in an try catch block in case of an IO Exception
	 */
	private static void startServer(){
		try{
			serverSocket = new ServerSocket(portNumber);
		} catch (IOException e){
			e.printStackTrace();
		}
	}

}

/**
 *
 */
class RequestHandler extends Thread
{
	/**
	 *
	 */
	private Socket socket;
	RequestHandler( Socket socket )
	{
		this.socket = socket;
	}

	/**
	 *
	 */
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
}