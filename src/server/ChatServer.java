import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;



public class ChatServer{

	private static ServerSocket serverSocket;
	private static int portNumber = 4444;

		public static void main(String[] args){
		portNumber = 4444; //If this doesn't work set up a different port (don't go lower than 1000 most likely in use already)
		serverSocket = null;
		/*
		* Setting up a listener on a specific port in a try catch block in case it fails.
		*/
		try {
			serverSocket = new ServerSocket(portNumber);
			acceptClients(); //This will need to be changed to only deal with Alice and Bob
		} catch (IOException e){
			System.err.println("Could not set up listener on: " + portNumber);
			System.exit(1);
		}
	}

	public static void acceptClients(){
		ArrayList clients = new ArrayList<ClientThread>(); //ArrayList for storing clients

	/*
	* So this is going to be in parallel but for the actual project
	* we only need two agents so it's unlikely threads will be necessary
	*/

		while(true){
			try{		//infinite loop
				Socket socket = serverSocket.accept();
				ClientThread client = new ClientThread(socket);
				Thread thread = new Thread(client);
				thread.start(); //Please don't give concurrency issues
				clients.add(client);
			} catch (IOException e) {
				System.out.println("Accept Failure on port: " + portNumber);
			}
		}
	}
}