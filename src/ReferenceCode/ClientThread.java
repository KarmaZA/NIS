import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Scanner;

public class ClientThread implements Runnable{
	
	private Socket socket;
	private Scanner in;
	private ChatServer server;

	private PrintWriter out;

	
	public ClientThread(ChatServer cs,Socket socket){
			this.socket=socket;
			this.server = cs;
	}

	@Override
	public void run(){
		try{
			out = new PrintWriter(socket.getOutputStream(), false);//true?
			in = new Scanner(socket.getInputStream());
			
			//While the socket is still connected, alive and not fucking over my soul
			while(!socket.isClosed()){
				if(in.hasNextLine()) {
					String input = in.nextLine();
					// NOTE: if you want to check server can read input, uncomment next line and check server file console.
					for (ClientThread client : server.getClients()) {
						PrintWriter clientOut = client.getWriter();
						if(clientOut != null){
							clientOut.write(input + "\r\n");
							clientOut.flush();
						}
					}
				}
			}
		}catch (IOException e){
			e.printStackTrace();
		}
	}
	
	public PrintWriter getWriter(){
		return out;
	}
}