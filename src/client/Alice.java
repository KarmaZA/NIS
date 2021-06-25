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
import java.util.Calendar;
import java.util.Objects;
import java.util.Scanner;

class Alice{
    private final static Scanner scanner = new Scanner(System.in);
    private final static int portNumber = 45554;
    private static String IP = "localhost";
    private final static String username = "Alice";

    private static String certificateExpiryDate;

    public static Key publicKey;
    private static Key privateKey;
    private static Key BobPublicKey;
    public static Key publicKeyCA;
    private static SecretKey masterAlice = null;

    static volatile boolean done = true;

    /**
     * The main function for the class Alice. Sets up the variables and keys to be used in the program
     * Creates a connection to Bob or requests a new port number if connection fails
     * Calls AuthenticateCommunication() to authenticate the communication with Bob using the AuthenticationServer
     * If authenticated starts the messaging.
     * @param args String array to take input into the main method
     * @throws Exception throws exception in Alice main
     */
    public static void main(String[] args) throws Exception {
        masterAlice = KeyGenerator.genMasterKeyFromString("w10PtdhELmt/ZPzcZjxFdg==");
        //get keys
        try {
            Key[] keypair = KeyGenerator.generateKeyPair();
            assert keypair != null;
            publicKey = keypair[0];
            privateKey = keypair[1];
        } catch (NullPointerException e){
            //Catch a possible Null Pointer Exception
            System.out.println("Key pair generation failed.");
        }
        System.out.println("Please input the IP of the computer you want to connect with or use 'localhost':");
        IP = scanner.nextLine();

        Socket socket = Connect(portNumber);

        while(socket == null){
            System.out.println("Please input a valid IP or 'localhost':");
            IP = scanner.nextLine();
            socket = Connect(portNumber);
        }
        //Authenticate communication
        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        boolean authenticated = RequestCommunication(in, out);
        if(authenticated){
            System.out.println("Authentication Succeeded");
            startMessaging(socket,in, out);
        } else {
            //Authentication failed. Assume it's malicious and end program
            System.exit(0);
        }


    }

    /**
     * Method to connect a socket with the port specified in parameters
     * @param portConnectionNumber The port number the socket will connect through
     * @return returns The connected socket or null if no connection made
     */
    private static Socket Connect(int portConnectionNumber) {
        try {
            Socket socket = new Socket(IP, portConnectionNumber);
            System.out.println("Socket on Alice set up");
            return socket;
        } catch (Exception e) {
            System.out.println("I have nothing to connect to :'(");
        }
        return null;
    }

    /**
     * Returns the Certificate of Public Key
     * @throws Exception Throws an exception in getCAPublicKey
     */
    private static void getCAPublicKey() throws Exception {
        Socket authServerSocket = Connect(45555);
        DataOutputStream out = new DataOutputStream(authServerSocket.getOutputStream());
        DataInputStream in = new DataInputStream(authServerSocket.getInputStream());

        out.writeUTF("REQKEY,null,null,null,null");
        int len = (int) in.readLong();
        byte[] pubKey = in.readNBytes(len);
        publicKeyCA = KeyGenerator.getCAPublicKey(new String(pubKey));
    }

    /**
     * Method to generate a certificate from the Authentication server
     * @param certificate the public key
     * @return Signed Hash of the public key
     */
    private static byte[] signCertificate(byte[] certificate){
        try {
            System.out.println("Generating a signed certificate.");
            Socket authServerSocket = Connect(45555);
            DataOutputStream outAuthServ = new DataOutputStream(authServerSocket.getOutputStream());
            DataInputStream inAuthServ = new DataInputStream(authServerSocket.getInputStream());

            System.out.println("Connected to CA.");

            certificate = Objects.requireNonNull(SecurityFunctions.encryptWithSharedKey(certificate,masterAlice));

            outAuthServ.writeUTF("SIGN," + certificate.length +",Alice,null,null");

            outAuthServ.write(certificate);
            System.out.println("Sent the certificate to the Authentication Server");
            String certify = inAuthServ.readUTF();
            String[] certifyArray = certify.split(",");

            certificate = inAuthServ.readNBytes(Integer.parseInt(certifyArray[2]));
            if (certifyArray[0].equals("SIGNED")){
                certificateExpiryDate = certifyArray[3];
                System.out.println("Signed certificate has been returned");
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
     * @param hashString The hashString is the encrypted hash from the CA
     * @return true if the certificate is validated.
     * @throws InvalidKeySpecException Throws an invalid key spec exception in getPublicKey
     * @throws NoSuchAlgorithmException Throws a no such algorithm exception in getPublicKey
     * @throws NoSuchProviderException Throws a no such provider exception in getPublicKey
     */
    private static boolean getPublicKey(byte[] cert, byte[] hashString) throws InvalidKeySpecException, NoSuchProviderException, NoSuchAlgorithmException {
        Calendar calendar = Calendar.getInstance();
        String dayOfTheYear = calendar.get(Calendar.DAY_OF_YEAR) + "";
        if(Integer.parseInt(dayOfTheYear) >= Integer.parseInt(certificateExpiryDate)){
            System.out.println("Certificate Expired");
            return false;
        }
        System.out.println("Certificate has not expired");

        byte[] hashToDecrypt = writeThread.joinByteArray(cert, certificateExpiryDate.getBytes());
        String checkHash = SecurityFunctions.hashString(hashToDecrypt);
        String decryptedSignature = SecurityFunctions.decryptWithAsymmetricKey(hashString, publicKeyCA);
        System.out.println("The hash has been decrypted");

        assert hashString!=null;
        if(checkHash.equals(decryptedSignature)){
            System.out.println("Signature of CA validated");
            cert = Base64.getDecoder().decode(cert);
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(cert);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
            BobPublicKey = keyFactory.generatePublic(publicKeySpec);
            System.out.println("Public key retrieved");
            return true;
        } else {
            return false;
        }
    }

    /**
     * Executes the authentication steps with the KDC using master keys and nonces to authenticate the
     * communication session between Alice and Bob and generate a session key. As well as validate that the
     * conversation is indeed between Alice and Bob.
     * @param inBob Reads in input stream from Bob
     * @param outBob Sends out datastream to Bob
     * @return true if the authentication is validated
     */
    private static boolean RequestCommunication(DataInputStream inBob, DataOutputStream outBob){
        try {
            getCAPublicKey();
            //request communication
            System.out.println("Request communication");
            //Header to request communication
            outBob.writeUTF("CMD,START,REQCOM," + username + ",null");
            System.out.println("Request has been sent.");

            String line = inBob.readUTF();
            String[] bobHeader = line.split(",");
            certificateExpiryDate = bobHeader[1];
            byte[] certificate = inBob.readNBytes(Integer.parseInt(bobHeader[2]));
            byte[] signedCertificate = inBob.readNBytes(Integer.parseInt(bobHeader[4]));
            System.out.println("Certificate Received");

            if(!getPublicKey(certificate, signedCertificate)){
                System.out.println("Invalid certificate");
                System.exit(1);
            }

            System.out.println("The certificate has been verified");
            System.out.println("Requesting certificate");

            certificate = Base64.getEncoder().encode(publicKey.getEncoded());
            signedCertificate = signCertificate(certificate);
            if(certificate == null) System.exit(1);

            System.out.println("The certificate has been signed");

            outBob.writeUTF("CMD," + certificateExpiryDate + "," + certificate.length + "," + signedCertificate.length + ",null");
            outBob.write(certificate);
            outBob.write(signedCertificate);
            System.out.println("Certificate sent");
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
     * @param in Takes in the data stream
     * @param out Outputs messaging data
     */
    private static void startMessaging(Socket socket, DataInputStream in, DataOutputStream out){
        // When we use IPs we will use preset ones
        try{
            //threads for sending and receiving messages/images
            readThread read = new readThread("Bob", socket, in, out, Alice.privateKey, BobPublicKey);
            writeThread write = new writeThread("Bob", scanner, socket, in, out, Alice.privateKey, BobPublicKey);
            read.start();
            write.start();
            while(done){}
            System.out.println("Bye Alice...");
            System.exit(0);
        }catch (Exception e) {
            System.out.println("Connection ended main");
            e.printStackTrace();
        }
    }
}