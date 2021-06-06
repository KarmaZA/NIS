import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class ClientThread extends ChatServer implements Runnable{
	
	private Socket socket;
	private BufferedReader in;
	private PrintWriter out;
	
	public ClientThread(Socket socket){
			this.socket=socket;
	}

	@Override
	public void run(){
		try{
			out = new PrintWriter(socket.getOutputSteam(), true);
			in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			
			//While the socket is still connected, alive and not fucking over my soul
			while(!socket.isClosed()){
					String input = in.ReadLine();
					if(input != null){
						for(ClientThread client : clients){
							client.getWriter().write(inputs);
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