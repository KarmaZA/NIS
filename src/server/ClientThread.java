public class ClientThread extends Chatserver implements Runnable{
	private Socket socket;
	
	public ClientThread(Socket socket){
			this.socket=socket;
	}
	
	@override
	public void run(){
			//TODO make thread relay messages;
	}
}