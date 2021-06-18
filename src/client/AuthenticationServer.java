import javax.crypto.SecretKey;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;

class AuthenticationServer{

    private static ServerSocket serverSocket;
    private static int portNumber = 45555;
    //Preset master key with Alice
    private static SecretKey masterAlice = null;
    //Preset master key with Bob
    private static SecretKey masterBob = null;

    /**
     * The main method of the class. Sets up the keys and starts the server listening. then when a connection comes in
     * it authenticates the keys of the session and sets up a session key
     */
    public static void main(String[] args){
        //Generating Master Keys from Strings
        masterAlice = KeyGenerator.genMasterKeyFromString("w10PtdhELmt/ZPzcZjxFdg==");
        masterBob = KeyGenerator.genMasterKeyFromString("055WVjVBB95Yaw6ZhRAWug==");
        startServer();
        System.out.println("The server has started");
        while(true){
            try{
                Socket socket = serverSocket.accept();
                System.out.println("Connection accepted");
                AcceptConnections(socket);
            }catch (IOException e){
                e.printStackTrace();
            }
        }

    }

    /**
     * starts the ServerSocket in an try catch block in case of an IO Exception
     */
    private static void startServer(){
        try{
            serverSocket = new ServerSocket(portNumber);
            System.out.println("Authentication server is listening on port " + portNumber);
        } catch (IOException e){
            e.printStackTrace();
        }
    }

    /**
     * Undergoes the KDC part of the authentication.
     * @param sckt the socket the connection is coming through
     */
    private static void AcceptConnections(Socket sckt){
        try
        {
            System.out.println( "Received a connection" );

            // Get input and output streams
            BufferedReader in = new BufferedReader( new InputStreamReader( sckt.getInputStream() ) );
            PrintWriter out = new PrintWriter( sckt.getOutputStream() );

            String nonce = in.readLine();
            System.out.println(nonce);
            //generate session key and encrypt (session key|request|nonce with Alice Master Key
            SecretKey sessionKey = KeyGenerator.genSharedKey();

            String AliceEncrypt = sessionKey.getEncoded() + "|" + nonce;
            System.out.println(AliceEncrypt);
            //AliceEncrypt.encrypt with master key
            AliceEncrypt = new String(Objects.requireNonNull(SecurityFunctions.encryptWithSharedKey(AliceEncrypt.getBytes(), masterAlice)));
            //System.out.println("Alice encrpyt is : " + AliceEncrypt);
            //System.out.println(SecurityFunctions.decryptWithSharedKey(AliceEncrypt.getBytes(),masterAlice));

            //Encrypt ticket Session|"Alice"|nonce with bob master key for Bob
            String BobEncrypt = Base64.getEncoder().encodeToString(sessionKey.getEncoded()) + "|Alice|" + nonce;
            //BobEncrypt with master key for bob
            BobEncrypt = new String(Objects.requireNonNull(SecurityFunctions.encryptWithSharedKey(BobEncrypt.getBytes(), masterBob)));

            AliceEncrypt += "|" + BobEncrypt;
            System.out.println(AliceEncrypt);
            //send back to Alice
            out.write(AliceEncrypt);
            out.flush();
            // Close our connection
            in.close();
            out.close();
            sckt.close();

            System.out.println( "Authentication completed closed" );
        }
        catch( Exception e )
        {
            e.printStackTrace();
        }
    }

}