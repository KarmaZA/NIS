import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;

class Bob{
    private static ServerSocket serverSocket;
    private String IP = "localhost";
    private static int portNumber = 45554;


    public static void main(String[] args){
        startServer();
        System.out.println("Bob is bobbing");
        try {
			Socket socket = serverSocket.accept();

			RequestHandler requestHandler = new RequestHandler(socket);
			requestHandler.start();
		} catch (IOException e){
        	System.out.println("Bob's bobbing did not bob up anything");
			e.printStackTrace();
		}
    }

    private static void startServer(){
        try{
            serverSocket = new ServerSocket(portNumber);
        } catch (IOException e){
			e.printStackTrace();
        }
    }
	
	/*private void saveFile(Socket clientSocket, String[] tempArr) throws Exception{
			DataInputStream datainputstream = new DataInputStream(clientSocket.getInputStream());
			FileOutputStream fileoutputstream = new FileOutputStream(tempArr[0]);
			
			byte[] buffer = new byte[4096];
			
			int read = 0;
			int totalRead = 0;
			int remaining = Integer.parseInt(tempArr[1]);
			read = datainputstream.read(buffer, 0, Math.min(buffer.length, remaining));
			while(read >0){
				totalRead += read;
				remaining -= read;
				fileoutputstream.write(buffer, 0, read);
			read = datainputstream.read(buffer, 0, Math.min(buffer.length, remaining);

			}
	}*/
	
}

class RequestHandler extends Thread
{
	private Socket socket;
	RequestHandler( Socket socket )
	{
		this.socket = socket;
	}

	@Override
	public void run()
	{
		try
		{
			System.out.println( "Received a connection" );

			// Get input and output streams
			BufferedReader in = new BufferedReader( new InputStreamReader( socket.getInputStream() ) );
			PrintWriter out = new PrintWriter( socket.getOutputStream() );

			String line = in.readLine();
			System.out.println(line);
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