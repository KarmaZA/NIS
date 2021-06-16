import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

class Alice{
    private String username = "Alice";
    private Scanner scanner = new Scanner(System.in);
    private static int portUpload = 45554;

    public static Key publicKey;
    public static Key privateKey; //Change back to private

    final String IP = "localhost";

    /**
     *
     * @param args String array to take input into the main method
     */
    public static void main(String[] args){
        //get keys
        try {
            Key[] keypair = KeyGenerator.generateKeyPair();
            publicKey = keypair[0];
            privateKey = keypair[1];
            SecretKey sharedkey = KeyGenerator.genSharedKey();
            try {
                byte[] encryptedonPGP = SecurityFunctions.PGPConfidentialityEncrypt("hello world", KeyGenerator.genSharedKey(), Alice.publicKey);
                String returned = SecurityFunctions.PGPConfidentialityDecrypt(encryptedonPGP, Alice.privateKey);
                System.out.println(returned);

                //this shows that the functions do work independently
                System.out.println(SecurityFunctions.decryptWithSharedKey(SecurityFunctions.encryptWithSharedKey("Hello world".getBytes(), sharedkey), sharedkey));
            } catch (Exception e){
                System.out.println("PGPConfidentialityEncrypt IO error || decryptWithSharedKey exception");
                e.printStackTrace();
            }
        } catch (NoSuchAlgorithmException e){
            System.out.println("Could not generate Key Pair");
            e.printStackTrace();
        }
        if(AuthenticateCommunication(Connect(portUpload))){
            //Write code for communication here
        } else {
            System.out.println("Authentication failed");
        }


    }

    /**
     *      *
     * This method will return true or false when authenticating communication with a user on a given port
     *
     * For the sake of this prac we're only connecting to one client port and not using threads
     * @param socket Socket for the port that the communication is authenticating from
     * @return return true if the authentication was successfull
     */
    private static boolean AuthenticateCommunication(Socket socket){
        try {
            //Set up IO streams
            String toSend = "Communication request";
            PrintStream outBob = new PrintStream(socket.getOutputStream());
            BufferedReader inBob = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            //STEP 1 request communication
            System.out.println("Step 1");
            outBob.println(toSend);
            System.out.println("Request has been sent.");

            //STEP 2 Receive Nonce from Bob
            System.out.println("Step 2");

            toSend = inBob.readLine();
            System.out.println("The Nonce from Bob is " + toSend);

            //STEP 3 send nonce to Auth Server
            System.out.println("Step 3");

            Socket authServerSocket = Connect(45555);
            PrintStream outAuthServ = new PrintStream(authServerSocket.getOutputStream());
            BufferedReader inAuthServ = new BufferedReader(new InputStreamReader(authServerSocket.getInputStream()));
            //Write some encryption here
            outAuthServ.println(toSend);

            //STEP 4 receive encrypted nonce from server
            System.out.println("Step 4");
            toSend = inAuthServ.readLine();
            System.out.println(toSend);

            //STEP 5 send semi-decrypted auth server to Bob
            System.out.println("Data sent to Bob");
            outBob.println("Step 5 semi decrypted from AS");


            //STEP 6 Receive shared key from Bob (Decrypted from AS)
            System.out.println("Step 6");
            toSend = inBob.readLine();
            System.out.println("The session key from Bob is " + toSend);

            return true;
        } catch (IOException e){
            System.out.println("No message, you've been ghosted");
            e.printStackTrace();
            return false;
        }
    }

    private static Socket Connect(int portConnectionNumber){
        try{
            Socket socket = new Socket("localhost", portConnectionNumber);
            System.out.println("Socket on Alice set up");
            return socket;
        } catch (Exception e){
            System.out.println("I have nothing to connect to :'(");
            e.printStackTrace();
        }
        return null;
    }
}