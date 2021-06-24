import javax.crypto.SecretKey;
import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class writeThread implements Runnable {

    private Thread write;
    private final String threadName;
    private final DataInputStream in;
    private final DataOutputStream out;
    private final Socket socket;
    private final Scanner scanner;
    private static Key senderPrivateKey;
    private static Key recieverPublicKey;

    /**
     * 
     * @param threadName Name of the thread
     * @param scanner scanner for user input
     * @param socket connection socket
     * @param in Data input Stream
     * @param out Data ooutput Stream
     * @param senderPrivateKey senders private key
     * @param recieverPublicKey receivers public key
     */
    writeThread(String threadName, Scanner scanner, Socket socket, DataInputStream in, DataOutputStream out,  Key senderPrivateKey, Key recieverPublicKey){
        this.threadName = threadName;
        this.scanner = scanner;
        this.in = in;
        this.out = out;
        this.socket = socket;
        this.senderPrivateKey = senderPrivateKey;
        this.recieverPublicKey = recieverPublicKey;
    }
    public void run(){
        // while() loop to keep checking for client commands (UPLOAD, DOWNLOAD, LIST, quit)
        try{
            while (true) {
                // prompt client to enter command
                System.out.println("Enter Message or [upload] to send an image with a caption or [quit] to exit:");
                // client enters message
                String message = scanner.nextLine();
                if (message.equals("quit")){
                    // << HEADER sent to server to signify a QUIT
                    out.writeUTF("CMD,quit,null,null,null");
                    // close input and output streams
                    in.close();
                    out.close();
                    Alice.done = false;
                    break;
                }
                if(message.equals("upload")){ //upload file name
                    System.out.println("Enter Filename:");
                    String fName = scanner.nextLine();
                    //check whether file is there to upload
                    File temp = new File(fName);
                    if (!temp.exists()) {
                        System.out.println("Cannot find file.");
                        continue;
                    }
                    //send header for other thread to download
                    out.writeUTF("Auth,I," + fName + ",null, null");
                    upload(fName,out, scanner); //uploads client header and image/caption
                }else{ //just a normal message
                    //basic messaging
                    out.writeUTF("Auth,M,null,null,null");
                    System.out.println("DEBUG:");
                    System.out.println("----------");


                    byte[] toSend = SecurityFunctions.PGPFullEncrypt(message.getBytes(),KeyGenerator.genSharedKey(),senderPrivateKey,recieverPublicKey);
                    out.writeLong(toSend.length);
                    out.write(toSend, 0, toSend.length);
                    System.out.println("Encrypted message sent to " + this.threadName);
                    System.out.println("----------");
                }
            }
        }catch (Exception e) {
            System.out.println("Connection ended");
            e.printStackTrace();
        }
    }
    /**
     * 
     * @param clientCommand String input from client
     * @param out Output Stream
     * @param scanner Scanner to take user input
     */
    public static void upload(String clientCommand, DataOutputStream out, Scanner scanner){
        try {
            // create new file with the name specified by the client
            File myFile = new File(clientCommand);
            System.out.println("Enter Caption for Image:");
            String caption = scanner.nextLine();
            // create byte array that will be used to store file content
            byte[] myByteArray = new byte[(int) myFile.length()];
            // FileInputStream -> BufferedInputStream -> DataInputStream -> byte array
            FileInputStream fis = new FileInputStream(myFile);
            BufferedInputStream bis = new BufferedInputStream(fis);
            DataInputStream dis = new DataInputStream(bis);
            dis.readFully(myByteArray, 0, myByteArray.length);
            // combine byte arrays
            System.out.println("DEBUG:");
            System.out.println("----------");
            System.out.println("ENCRYPTING IMAGE");
            byte[] myByteArraySecure = SecurityFunctions.PGPFullEncrypt(myByteArray, KeyGenerator.genSharedKey(), senderPrivateKey, recieverPublicKey );
            System.out.println("ENCRYPTING CAPTION");
            byte[] captionSecure = SecurityFunctions.PGPFullEncrypt(caption.getBytes(), KeyGenerator.genSharedKey(), senderPrivateKey, recieverPublicKey );


            byte[] payload = joinByteArray(myByteArraySecure, captionSecure);


            // << PAYLOAD sent to server containing length of byte array to upload
            out.writeLong(myByteArraySecure.length);
            out.writeLong(captionSecure.length);
            // << PAYLOAD sent to server containing byte array
            out.write(payload, 0, payload.length);

            out.flush();
            dis.close();
            System.out.println("----------");
            System.out.println("File sent: " + clientCommand);

        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
    /**
     *
     * @param image byte array of image
     * @param caption byte array of caption
     * @return combined byte array of image and caption
     */
    public static byte[] joinByteArray(byte[] image, byte[] caption){
        return ByteBuffer.allocate(image.length + caption.length)
                .put(image)
                .put(caption)
                .array();
    }

    public void start(){
        if(write == null){
            write = new Thread (this,threadName);
            write.start();
        }
    }

}