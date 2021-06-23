import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;
import java.util.Scanner;

class Alice{
    //Preset master key with Alice
    private static SecretKey masterAlice = null;


    private final static Scanner scanner = new Scanner(System.in);
    private static int portUpload = 45554;

    private final static String username = "Alice";

    private static SecretKey communicationSessionKey;

    public static Key publicKey;
    private static Key privateKey;
    private static Key BobPublicKey;
    public static Key publicKeyCA;
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
            publicKeyCA = KeyGenerator.getCAPublicKey();
            Key[] keypair = KeyGenerator.generateKeyPair();
            assert keypair != null;
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
        boolean authenticated = RequestCommunication(in, out);
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

    private static byte[] signCertificate(byte[] certificate){
        try {
            System.out.println("Generating a signed certificate.    " + new String(certificate));
            Socket authServerSocket = new Socket("localhost", 45555);
            DataOutputStream outAuthServ = new DataOutputStream(authServerSocket.getOutputStream());
            DataInputStream inAuthServ = new DataInputStream(authServerSocket.getInputStream());
            System.out.println("Connected to CA.");

            certificate = Objects.requireNonNull(SecurityFunctions.encryptWithSharedKey(certificate,masterAlice));

            outAuthServ.writeUTF("SIGN," + certificate.length +",Alice,null,null");

            outAuthServ.write(certificate);
            String certify = inAuthServ.readUTF();
            String[] certifyArray = certify.split(",");

            certificate = inAuthServ.readNBytes(Integer.parseInt(certifyArray[2]));
            //certificate = SecurityFunctions.decryptWithAsymmetricKey(certificate,publicKeyCA).getBytes();
            System.out.println(new String(certificate));
            if (certifyArray[0].equals("SIGNED")){
                return certificate;
            }
        } catch (Exception e) {
            System.out.println("I have nothing to connect to :'(");
        }
        return null;
    }

    /**
     * Method to verify that the connection is to bob. Decrypts the string with the CA public key and makes
     * sure that it says bob who we are trying to talk to.
     * @param cert The encoded String that is signed by the CA with their private key
     * @return true if the certificate is validated.
     */
    private static boolean getPublicKey(byte[] cert, byte[] hashString) throws InvalidKeySpecException, NoSuchProviderException, NoSuchAlgorithmException {
        //Use CA public key
        //cert = SecurityFunctions.decryptWithAsymmetricKey(cert.getBytes(),publicKeyCA);
        //cert = SecurityFunctions.decryptWithAsymmetricKey(cert,publicKeyCA).getBytes();
        String checkHash = SecurityFunctions.hashString(cert);
        String decryptedSignature = SecurityFunctions.decryptWithAsymmetricKey(hashString, publicKeyCA);
        System.out.println("The hashes are");
        System.out.println(checkHash);
        System.out.println(decryptedSignature);
        assert hashString!=null;
        if(checkHash.equals(decryptedSignature)){
            System.out.println("It works");
            cert = Base64.getDecoder().decode(cert);
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(cert);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
            BobPublicKey = keyFactory.generatePublic(publicKeySpec);
            return true;
        } else {
            return false;
        }
    }

    /**
     * Executes the authentication steps with the KDC using master keys and nonces to authenticate the
     * communication session between Alice and Bob and generate a session key. As well as validate that the
     * conversation is indeed between Alice and Bob.
     * @return true if the authentication is validated
     */
    private static boolean RequestCommunication(DataInputStream inBob, DataOutputStream outBob){
        try {
            publicKeyCA = KeyGenerator.getCAPublicKey();
            //STEP 1 request communication
            System.out.println("Step 1: Request communication");
            //Header to request communication
            outBob.writeUTF("CMD,START,REQCOM," + username + ",null");
            System.out.println("Request has been sent.");

            //STEP 2 Receive Nonce from Bob

            //toSend = inBob.readLine();
            System.out.println("Step 2");

            //If this is a problem make it two lines
            String line = inBob.readUTF();
            String[] bobHeader = line.split(",");
            byte[] certificate = inBob.readNBytes(Integer.parseInt(bobHeader[2]));
            byte[] signedCertificate = inBob.readNBytes(Integer.parseInt(bobHeader[4]));
            System.out.println("Certificate Received");

            if(!getPublicKey(certificate, signedCertificate)){
                System.out.println("Invalid certificate");
                System.exit(1);
            }

            System.out.println("The certificate has been verified");
            String nonce = bobHeader[1];


            //STEP 3 send nonce to Auth Server
            certificate = Base64.getEncoder().encode(publicKey.getEncoded());
            signedCertificate = signCertificate(certificate);
            if(certificate == null) System.exit(1);
            //String certificate = "bob";

            System.out.println("The certificate has been signed");

            outBob.writeUTF("CMD," + nonce + "," + certificate.length + "," + signedCertificate.length + ",null");
            outBob.write(certificate);
            outBob.write(signedCertificate);
            return true;

        } catch (Exception e){
            System.out.println("No message, you've been ghosted");
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Passes the socket for the communication with Bob. This method will only be called once the communication
     * session has been authenticated.
     * @param socket The socket connected to Bob
     */
    private static void startMessaging(Socket socket, DataInputStream in, DataOutputStream out){
        // When we use IPs we will use preset ones
        try{
            // while() loop for password authentication
            while (true) {
                // client enters server password
                System.out.println("Enter: <Password>");
                String clientPassword = scanner.nextLine();
                // << HEADER sent to server to check password
                String publicKeyString =  new String(Base64.getEncoder().encode(publicKey.getEncoded()));
                out.writeUTF("CMD;START;" + clientPassword + ";" + publicKeyString + ";null");
                // >> HEADER received from server detailing if password is correct or not
                String[] serverHeader = in.readUTF().split(";");

                // check if password is correct or not
                if (serverHeader[4].equals("success")) {
                    System.out.println("Password Correct");
                    //extract Bob's public key
                    byte [] publicKeyBytes = Base64.getDecoder().decode(serverHeader[1].getBytes());
                    EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
                    Key BobPublicKey1 = keyFactory.generatePublic(publicKeySpec);
                    if(BobPublicKey.equals(BobPublicKey1)) System.out.println("True");
                    // password is correct, break out of while() loop
                    break;
                }
                // password is incorrect, repeat loop
                System.out.println("Password Incorrect");
            }

            //threads for sending and receiving messages/images
            readThread read = new readThread("Bob", socket, in, out, Alice.privateKey, BobPublicKey);
            writeThread write = new writeThread("Bob", scanner, socket, in, out, Alice.privateKey, BobPublicKey);
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