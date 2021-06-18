import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.Key;
import java.util.Arrays;
import java.util.Scanner;

class Alice{
    //Preset master key with Alice
    private static SecretKey masterAlice = null;

    private final static Scanner scanner = new Scanner(System.in);
    private static int portUpload = 45554;

    public static Key publicKey;
    public static Key privateKey; //TODO change back to private

    //final String IP = "localhost";

    //For two way messaging
    static volatile boolean done = true;

    /**
     * The main function for the class Alice. Sets up the variables and keys to be used in the program
     * Creates a connection to Bob or requests a new port number if connection fails
     * Calls AuthenticateCommunication() to authenticate the communication with Bob using the AuthenticationServer
     * If authenticated starts the messaging.
     *
     */
    public static void main(String[] args) throws Exception {
        masterAlice = KeyGenerator.genMasterKeyFromString("w10PtdhELmt/ZPzcZjxFdg==");
        //get keys
        try {
            Key[] keypair = KeyGenerator.generateKeyPair();
            publicKey = keypair[0];
            privateKey = keypair[1];
        } catch (NullPointerException e){
            //Catch a possible Null Pointer Exception
            System.out.println("Key pair generation failed.");
        }
        //Connect to socket
        Socket socket = Connect(portUpload);
        //Socket connection failed try new port or quit

        while(socket == null){
            System.out.println("Port Connection failed please input a new port number (0 to exit):");
            portUpload = Integer.parseInt(scanner.nextLine());
            if(portUpload == 0){ System.exit(0);}
            socket = Connect(portUpload);
        }
        //Authenticate communication
        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        boolean authenticated = AuthenticateCommunication(in, out);
        if(authenticated){
            startMessaging(socket,in, out);
        } else {
            //Authentication failed. Assume it's malicious and end program
            System.exit(0);
        }


    }

    /**
     * method to connect a socket with the port specified in parameters
     * @param portConnectionNumber the port number the socket will connect through
     * @return returns the connected socket or null if no connection made
     */
    private static Socket Connect(int portConnectionNumber) {
        try {
            Socket socket = new Socket("localhost", portConnectionNumber);
            System.out.println("Socket on Alice set up");
            return socket;
        } catch (Exception e) {
            System.out.println("I have nothing to connect to :'(");
        }
        return null;
    }

    /**
     * Executes the authentication steps with the KDC using master keys and nonces to authenticate the
     * communication session between Alice and Bob and generate a session key. As well as validate that the
     * conversation is indeed between Alice and Bob.
     * @return true if the authentication is validated
     */
    private static boolean AuthenticateCommunication(DataInputStream inBob, DataOutputStream outBob){
        try {
            //STEP 1 request communication
            System.out.println("Step 1");
            //Header to request communication
            outBob.writeUTF("CMD,START,REQCOM,null,null");
            System.out.println("Request has been sent.");
            //STEP 2 Receive Nonce from Bob

            //toSend = inBob.readLine();
            System.out.println("Step 2");

            //If this is a problem make it two lines
            String line = inBob.readUTF();
            String[] bobHeader = line.split(",");
            String nonce = bobHeader[1];
            System.out.println("The Nonce from Bob is " + nonce);



            //STEP 3 send nonce to Auth Server
            System.out.println("Step 3");
            System.out.println("Sending request and nonce to authentication server for verification");
            Socket authServerSocket = Connect(45555);
            DataOutputStream outAuthServ = new DataOutputStream(authServerSocket.getOutputStream());
            DataInputStream inAuthServ = new DataInputStream(authServerSocket.getInputStream());

            //Check header with AuthServ
            outAuthServ.writeUTF("AUTH,Bob,Alice," + nonce + ",null");

            //STEP 4 receive encrypted nonce from server
            System.out.println("Step 4");
            long aliceSize = inAuthServ.readLong();
            //long bobSize = inAuthServ.readLong();
            byte[] payload = inAuthServ.readAllBytes();
            byte[] aliceBuffer = Arrays.copyOfRange(payload, 0, (int)aliceSize);
            byte[] bobBuffer = Arrays.copyOfRange(payload, (int)aliceSize,payload.length);

            byte[] sessionKey = checkString(aliceBuffer, nonce);
            //If the nonce does not match the session key returns null
            if (sessionKey == null){
                //Terminate connection first for safety
                inBob.close();
                outBob.close();
                //inform user
                System.out.println("Authentication Failure");
                System.out.println("Program Exiting to avoid malicious connection");
                //return false
                return false;
            }


            //STEP 5 send semi-decrypted auth server to Bob
            System.out.println("Step 5 Data sent to Bob");
            System.out.println(bobBuffer.length);
            outBob.writeLong(bobBuffer.length);
            outBob.write(bobBuffer, 0 , bobBuffer.length);

            //STEP 6 Receive shared key from Bob (Decrypted from AS)
            System.out.println("Step 6");
            //toSend = inBob.readLine();
            //verify this matches our session key
            //System.out.println("The session key from Bob is " + toSend);

            inAuthServ.close();
            outAuthServ.close();
            return true;

        } catch (Exception e){
            System.out.println("No message, you've been ghosted");
            e.printStackTrace();
            return false;
        }
    }

    private static byte[] checkString(byte[] encoded, String nonce) throws Exception {
        //This is working without encryption/decryption
        //The right amount of data is getting here
        try {
            System.out.println(new String(encoded));
            byte[] sessionkey = Arrays.copyOfRange(encoded, 0, encoded.length - 17);
            System.out.println("Session key: " + new String(sessionkey));
            String nonceCheck = new String(Arrays.copyOfRange(encoded, encoded.length - 16, encoded.length));
            System.out.println(nonce);
            if (nonce.equals(nonceCheck)) {
                return sessionkey;
            } else {
                return null;
            }
        } catch (Exception e){
            //Any form of exception constitutes authentication failure
            return null;
        }
    }

    /**
     * Passes the socket for the communication with Bob. This method will only be called once the communication
     * session has been authenticated.
     * @param socket The socket connected to Bob
     */
    private static void startMessaging(Socket socket, DataInputStream in, DataOutputStream out){
            // scanner used for all client input
            //Scanner scanner = new Scanner(System.in);

            // client enters IP address to connect to server
            // System.out.println("Enter: <IP>");
            // String clientIP = scanner.nextLine();

            System.out.println("Connecting...");

            // connect to server on designated IP address and port number 59897
            try{

                // If connection is successful, this block will run. Otherwise, connection will time out.
                System.out.println("Connection Successful");

                // input and output streams to read and write from server


                // while() loop for password authentication
                while (true) {
                    // client enters server password
                    System.out.println("Enter: <Password>");
                    String clientPassword = scanner.nextLine();
                    // << HEADER sent to server to check password
                    out.writeUTF("CMD,START," + clientPassword + ",null,null");
                    // >> HEADER received from server detailing if password is correct or not
                    String[] serverHeader = in.readUTF().split(",");
                    System.out.println(serverHeader);
                    // check if password is correct or not
                    if (serverHeader[4].equals("success")) {
                        System.out.println("Password Correct");
                        // password is correct, break out of while() loop
                        break;
                    }
                    // password is incorrect, repeat loop
                    System.out.println("Password Incorrect");
                }
                //threads for sending and receiving messages/images
                readThread read = new readThread("Bob", socket, in, out);
                writeThread write = new writeThread("Bob", scanner, socket, in, out);
                read.start();
                write.start();
                while(done){

                }
                System.out.println("Bye Alice...");
                System.exit(0);
            }catch (Exception e) {
                System.out.println(e);
                System.out.println("Connection ended main");
            }
        }
    }