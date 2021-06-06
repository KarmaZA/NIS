public class Client{
	public static void main(String[] args){
		Socket socket = null;
		int portNumber = 4444; //We Make sure it's connecting to the port with the listener on it
		try{
			socket = new Socket("localhost",portNumber);
			Thread.sleep(1000)
			Thread server = new Thread(new ServerThread(socket));
			server.start();
		} catch (IOException e) {
			System.err.println("Client.java;;No connection made on port: " + portNumber);
			e.printStackTrace();
		} catch (InterruptedException e){
			System.err.println("Client.java;;No connection made on port: " + portNumber);
			e.printStackTrace();
		}
	}	
}