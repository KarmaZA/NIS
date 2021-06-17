import javax.crypto.SecretKey;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
/*
Haven't done or even started here yet
 */
class AuthenticationServer{

    private static ServerSocket serverSocket;
    private static int portNumber = 45555;
    //Preset master key with Alice
    private static final SecretKey masterAlice = null;
    //Preset master key with Bob
    private static final SecretKey masterBob = null;


    public static void main(String[] args){
        startServer();
        System.out.println("The server has started");
        try{
            Socket socket = serverSocket.accept();
            System.out.println("Connection accepted");
            AcceptConnections(socket);
        }catch (IOException e){
            e.printStackTrace();
        }

    }

    private static void startServer(){
        try{
            serverSocket = new ServerSocket(portNumber);
            System.out.println("Authentication server is listening on port " + portNumber);
        } catch (IOException e){
            e.printStackTrace();
        }
    }

    private static void AcceptConnections(Socket sckt){
        try
        {
            System.out.println( "Received a connection" );

            // Get input and output streams
            BufferedReader in = new BufferedReader( new InputStreamReader( sckt.getInputStream() ) );
            PrintWriter out = new PrintWriter( sckt.getOutputStream() );

            String line = in.readLine();
            System.out.println(line);
            //Bob's reply
            out.write("Step 4 here is the encryption returned");
            out.flush();
            // Close our connection
            in.close();
            out.close();
            sckt.close();

            System.out.println( "Connection closed" );
        }
        catch( Exception e )
        {
            e.printStackTrace();
        }
    }

}