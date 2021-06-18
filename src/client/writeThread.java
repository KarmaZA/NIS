import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.Scanner;
import java.io.OutputStream;
import java.io.FileOutputStream;

public class writeThread implements Runnable {

    private Thread write;
    private String threadName;
    private DataInputStream in;
    private DataOutputStream out;
    private Socket socket;
    private Scanner scanner;

    writeThread(String threadName, Scanner scanner, Socket socket, DataInputStream in, DataOutputStream out){
        this.threadName = threadName;
        this.scanner = scanner;
        this.in = in;
        this.out = out;
        this.socket = socket;
    }
    public void run(){
        // while() loop to keep checking for client commands (UPLOAD, DOWNLOAD, LIST, quit)
        try{
            while (true) {
                // prompt client to enter command
                System.out.println("Enter Message or [Upload] to send Image or [quit] to exit:");
                // client enters message
                String message = scanner.nextLine(); 
                if (message.equals("quit")){
                    // << HEADER sent to server to signify a QUIT
                    out.writeUTF("CMD,quit,null,null,null");
                    // close input and output streams
                    in.close();
                    out.close();
                    Client.done = false;
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
                }else{
                    //basic messaging
                    out.writeUTF("Auth,M,null,null,null");
                    out.writeUTF(message);
                }            
            }
        }catch (Exception e) {
                System.out.println(e);
                System.out.println("Connection ended");
            } 
    }
    /**
     * upload file
     * @param clientCommand file name given as input
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
    /**
     * 
     * @param image byte array
     * @param caption byte array
     * @return combined byte array
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