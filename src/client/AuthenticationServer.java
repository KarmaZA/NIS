import javax.crypto.SecretKey;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.util.Base64;
import java.util.Calendar;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

class AuthenticationServer{

    private static ServerSocket serverSocket;
    private static final int portNumber = 45555;
    //Preset master key with Alice
    private static SecretKey masterAlice = null;
    //Preset master key with Bob
    private static SecretKey masterBob = null;

    public static Key publicKey;
    private static Key privateKey;

    /**
     * The main method of the class. Sets up the keys and starts the server listening. then when a connection comes in
     * it authenticates the keys of the session and sets up a session key
     * @param args Takes in the string parameters for the main function
     */
    public static void main(String[] args) {
        try {
            Key[] keypair = KeyGenerator.generateKeyPair();
            assert keypair!=null;
            publicKey = keypair[0];
            privateKey = keypair[1];
            FileWriter outFile = new FileWriter("public.txt");
            outFile.write(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
            outFile.close();

        } catch (Exception e){
            //Catch a possible Null Pointer Exception
            System.out.println("Key pair generation failed.");
            e.printStackTrace();
        }
        //Generating Master Keys from Strings
        masterAlice = KeyGenerator.genMasterKeyFromString("w10PtdhELmt/ZPzcZjxFdg==");
        masterBob   = KeyGenerator.genMasterKeyFromString("055WVjVBB95Yaw6ZhRAWug==");
        startServer();
        System.out.println("The server has started");
        try {
            ExecutorService pool = Executors.newFixedThreadPool(20);
            // server socket continuously listens for client connections
            while (true) {
                // when a client connects to server socket, the new socket is run in a separate thread
                pool.execute(new RequestHandler(serverSocket.accept()));
                System.out.println("new socket");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * starts the ServerSocket in an try catch block in case of an IO Exception
     */
    private static void startServer() {
        try {
            serverSocket = new ServerSocket(portNumber);
            System.out.println("Authentication server is listening on port " + portNumber);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static class RequestHandler implements Runnable{
        private final Socket socket;

        RequestHandler(Socket socket){
            this.socket = socket;
        }

        /**
         * Undergoes the KDC part of the authentication.
         */
        @Override
        public void run(){
            try {
                System.out.println("Received a connection");

                // Get input and output streams
                DataInputStream in = new DataInputStream(socket.getInputStream());
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());

                String header = in.readUTF();
                String[] headerArray = header.split(",");
                if(headerArray[0].equals("SIGN")){
                    generateCertificate(headerArray,in,out);
                    in.close();
                    out.close();
                    socket.close();
                }
                if(headerArray[0].equals("REQKEY")){
                    sendPublicKey(out);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        private static void sendPublicKey(DataOutputStream out) throws IOException {
            byte[] pubKeyToSend = (Base64.getEncoder().encodeToString(publicKey.getEncoded())).getBytes();
            out.writeLong(pubKeyToSend.length);
            out.write(pubKeyToSend);
        }

        /**
         * Generates a signed hash of the public key sent to it by a trusted source
         * @param header UTF header
         * @param in input stream for data
         * @param outWrite write data back to client
         * @throws Exception For failure
         */
        private void generateCertificate(String[] header, DataInputStream in, DataOutputStream outWrite) throws Exception {
            byte[] certificate;
            int certificateLength = Integer.parseInt(header[1]);
            certificate = in.readNBytes(certificateLength);
            System.out.println(header[1]);

            if (header[2].equals("Bob")){
                certificate = SecurityFunctions.decryptWithSharedKey(certificate, masterBob);
                //encrypt with private key

            }else if (header[2].equals("Alice")){
                certificate = SecurityFunctions.decryptWithSharedKey(certificate, masterAlice);
                System.out.println(new String(certificate));
                //encrypt with private key
            } else {
                certificate = "unknown".getBytes();
            }
            Calendar calendar = Calendar.getInstance();
            calendar.add(Calendar.DAY_OF_YEAR, 1);
            String dayOfTheYear = calendar.get(Calendar.DAY_OF_YEAR) + "";
            System.out.println("Tomorrow is " + dayOfTheYear);

            System.out.println("Signing the certificate");
            certificate = writeThread.joinByteArray(certificate, dayOfTheYear.getBytes());
            String keyHash = SecurityFunctions.hashString(certificate);
            byte[] hashToSend =  SecurityFunctions.encryptWithAsymmetricKey(keyHash, privateKey);

            assert hashToSend != null;
            outWrite.writeUTF("SIGNED," + certificate.length + "," + hashToSend.length + ","+ dayOfTheYear + ",null");//+ dateString + ",null");
            //outWrite.write(certificate);
            outWrite.write(hashToSend);
            outWrite.close();
        }

    }
}