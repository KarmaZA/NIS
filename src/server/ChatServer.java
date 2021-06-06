import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

import java.util.List;

//https://gist.github.com/fliedonion/1002293af6fd043fbd6e729c13018562

public class ChatServer{

	private ServerSocket serverSocket;
	private static int portNumber = 4444;
	private int serverPort;
	private List<ClientThread> clients;

	public static void main(String[] args) {
		ChatServer server = new ChatServer(portNumber);
		server.startServer();
	}

	public ChatServer(int PN){ this.serverPort =PN; }

	private void startServer(){
		serverSocket = null;
		/*
		* Setting up a listener on a specific port in a try catch block in case it fails.
		*/
		try {
			serverSocket = new ServerSocket(portNumber);
			acceptClients(serverSocket); //This will need to be changed to only deal with Alice and Bob
		} catch (IOException e){
			System.err.println("Could not set up listener on: " + portNumber);
			System.exit(1);
		}
	}

	public void acceptClients(ServerSocket serverSocket){
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