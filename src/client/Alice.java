import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.Key;
import java.util.Scanner;

class Alice{
    //Preset master key with Alice
    private static final SecretKey masterAlice = null;

    private final String username = "Alice";
    private final static Scanner scanner = new Scanner(System.in);
    private static int portUpload = 45554;

    public static Key publicKey;
    public static Key privateKey; //TODO change back to private

    final String IP = "localhost";

    /**
     *
     * @param args
     */
    public static void main(String[] args) throws Exception {
        //get keys
        try {
            Key[] keypair = KeyGenerator.generateKeyPair();
            publicKey = keypair[0];
            privateKey = keypair[1];
        } catch (NullPointerException e){
            //Catch a possible Null Pointer Exception
            System.out.println("Key pair generation failed.");
        }

        SecretKey sharedkey= KeyGenerator.genSharedKey();
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
        boolean authenticated = AuthenticateCommunication(socket);
        if(authenticated){
            startMessaging(socket);
        } else {
            //Authentication failed. Assume it's malicious and end program
            System.out.println("Authentication Failed");
            System.exit(0);
        }

        /* I don't know if this is needed
        byte[] encryptedonPGP = SecurityFunctions.PGPConfidentialityEncrypt("hello world", KeyGenerator.genSharedKey(), Alice.publicKey);
        String returned = SecurityFunctions.PGPConfidentialityDecrypt(encryptedonPGP, Alice.privateKey);
        System.out.println(returned);

        //this shows that the functions do work independently
        System.out.println(SecurityFunctions.decryptWithSharedKey(SecurityFunctions.encryptWithSharedKey("Hello world".getBytes(), sharedkey), sharedkey));
        */
    }

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

            //toSend = inBob.readLine();
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
            //toSend = inBob.readLine();
            System.out.println("The session key from Bob is " + toSend);

            inAuthServ.close();
            outAuthServ.close();
            return true;

        } catch (IOException e){
            System.out.println("No message, you've been ghosted");
            e.printStackTrace();
            return false;
        }
    }

    private static void startMessaging(Socket socket){
        // scanner used for all client input
        Scanner scanner = new Scanner(System.in);

        // client enters IP address to connect to server
        // System.out.println("Enter: <IP>");
        // String clientIP = scanner.nextLine();

        System.out.println("Connecting...");

        // connect to server on designated IP address and port number 59897
        try{

            // If connection is successful, this block will run. Otherwise, connection will time out.
            System.out.println("Connection Successful");

            // input and output streams to read and write from server
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            // while() loop for password authentication
            while (true) {
                // client enters server password
                System.out.println("Enter: <Password>");
                String clientPassword = scanner.nextLine();
                // << HEADER sent to server to check password
                out.writeUTF("CMD,START," + clientPassword + ",null,null");

                // >> HEADER received from server detailing if password is correct or not
                String[] serverHeader = in.readUTF().split(",");

                // check if password is correct or not
                if (serverHeader[4].equals("success")) {
                    System.out.println("Password Correct");
                    // password is correct, break out of while() loop
                    break;
                }
                // password is incorrect, repeat loop
                System.out.println("Password Incorrect");
            }

            // while() loop to keep checking for client commands (UPLOAD, DOWNLOAD, LIST, quit)
            while (true) {
                // prompt client to enter command
                System.out.println("Enter Message or [Upload] to send Image or [quit] to exit:");
                // client enters message
                String message = scanner.nextLine();
                if (message.equals("quit")){
                    System.out.println("Disconnecting from server...");
                    // << HEADER sent to server to signify a QUIT
                    out.writeUTF("CMD,quit,null,null,null");
                    // close input and output streams
                    in.close();
                    out.close();
                    break;
                }
                if(message.equals("Upload")){
                    System.out.println("Enter Filename:");
                    String fName = scanner.nextLine();
                    //check whether file is there to upload
                    File temp = new File(fName);
                    if (!temp.exists()) {
                        System.out.println("Cannot find file.");
                        continue;
                    }
                    //send header for Bob to download
                    out.writeUTF("Auth,I," + fName + ",null, null");
                    upload(fName, in,out, scanner); //uploads client header and image/caption
                    String [] reply = in.readUTF().split(",");
                    if(reply[4].equals("success")){
                        System.out.println("Image sent to Bob");
                    }else if(reply[4].equals("failed")){
                        System.out.println("Image failed to send");
                    }
                }else{
                    //basic messaging
                    out.writeUTF("Auth,M,null,null,null");
                    out.writeUTF(message);
                }

            }
        } catch (IOException e){
            System.out.println("IOException in startMessaging");
            e.printStackTrace();
        }
    }

    /**
     * upload file
     * @param clientCommand
     */
    public static void upload(String clientCommand,DataInputStream in, DataOutputStream out, Scanner scanner){

        try {

            // create new file with the name specified by the client
            File myFile = new File(clientCommand);
            System.out.println("Enter Caption for Image:");
            String caption = scanner.nextLine();

            // create byte array that will be used to store file content
            byte[] mybytearray = new byte[(int) myFile.length()];
            // FileInputStream -> BufferedInputStream -> DataInputStream -> byte array
            FileInputStream fis = new FileInputStream(myFile);
            BufferedInputStream bis = new BufferedInputStream(fis);
            DataInputStream dis = new DataInputStream(bis);
            dis.readFully(mybytearray, 0, mybytearray.length);
            // combiine byte arrays
            byte[] payload = joinByteArray(mybytearray, caption.getBytes());

            //SECURE MESSAGE??


            // << PAYLOAD sent to server containing length of byte array to upload
            out.writeLong(mybytearray.length);
            out.writeLong(caption.getBytes().length);
            // << PAYLOAD sent to server containing byte array
            out.write(payload, 0, payload.length);

            out.flush();
            dis.close();
            System.out.println("File sent: " + clientCommand);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    //combine two arrays
    public static byte[] joinByteArray(byte[] image, byte[] caption){
        return ByteBuffer.allocate(image.length + caption.length)
                .put(image)
                .put(caption)
                .array();
    }

    /**
     * check if string is digit
     * @param strNum
     * @return
     */
    public static boolean isInteger(String strNum){
        if(strNum == null){
            return false;
        }
        try{
            int num = Integer.parseInt(strNum);
        }
        catch(NumberFormatException nfe){
            return false;
        }
        return true;
    }
}