import java.net.Socket;
import java.io.*;
import java.util.LinkedList;
import java.util.Scanner;

public class ServerThread implements Runnable{
	private Socket socket;
	private String name;
	private BufferedReader serverIn;
	private BufferedReader userIn;
	private PrintWriter out;
	private final LinkedList<String> messagesToSend;
	private boolean hasMessage = false;
	
	public ServerThread(Socket socket, String username){

		this.socket = socket;
		name = username;
		messagesToSend = new LinkedList<String>();
	}

	public void addNextMessage(String message){
		synchronized (messagesToSend){
			hasMessage = true;
			messagesToSend.push(message);
		}
	}

	@Override
	public void run(){

		System.out.println("Welcome: " + name);
		System.out.println("Local port: " + socket.getLocalPort());
		System.out.println("Server= " + socket.getRemoteSocketAddress() + ":" + socket.getPort());

		try{
			PrintWriter serverOut = new PrintWriter(socket.getOutputStream(), false);
			InputStream serverInStream = socket.getInputStream();
			Scanner serverIn = new Scanner(serverInStream);
			// BufferedReader userBr = new BufferedReader(new InputStreamReader(userInStream));
			// Scanner userIn = new Scanner(userInStream);

			while(!socket.isClosed()){
				if(serverInStream.available() > 0){
					if(serverIn.hasNextLine()){
						System.out.println(serverIn.nextLine());
					}
				}
				if(hasMessage){
					String nextSend = "";
					synchronized(messagesToSend){
						nextSend = messagesToSend.pop();
						hasMessage = !messagesToSend.isEmpty();
					}
					serverOut.println(name + " > " + nextSend);
					serverOut.flush();
				}
			}
		} catch (IOException e){
			e.printStackTrace();
		}
	}
}