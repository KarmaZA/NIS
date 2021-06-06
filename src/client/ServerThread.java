import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.io.IOException;

public class ServerThread implements Runnable{
	private Socket socket;
	private String name;
	private BufferedReader serverIn;
	private BufferedReader userIn;
	private PrintWriter out;
	
	public ServerThread(Socket socket){
			this.socket = socket;
	}

	@Override
	public void run(){
		try{
			out = new PrintWriter(socket.getOutputStream(), true);
			serverIn = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			userIn = new BufferedReader(new InputStreamReader(System.in));
			
			//Run whiole the server is alove
			while(!socket.isClosed()){
				if(serverIn.ready()){
					String input = serverIn.readLine();
					if(input != null){
							System.out.println(input);
					}
				}
				if(userIn.ready()) {
					out.println(name + " > " + userIn.readLine());
				}
			}
		} catch (IOException e){
			e.printStackTrace();
		}
	}
}