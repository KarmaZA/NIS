import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.io.OutputStream;
import java.io.FileOutputStream;
import java.security.Key;

public class readThread implements Runnable {

    private Thread read;
    private String threadName;
    private DataInputStream in;
    private DataOutputStream out;
    private Socket socket;
    private static SecretKey communicationSessionKey;
    private static Key receiverPrivate;
    public static  Key senderPublic;
    

    public readThread(String threadName, Socket socket, DataInputStream in, DataOutputStream out,Key receiverPrivate, Key senderPublic){
        this.threadName = threadName;
        this.socket  = socket;
        this.in = in;
        this.out = out;
        this.receiverPrivate = receiverPrivate;
        this.senderPublic = senderPublic;
    }

    @Override
    public void run(){
        String clientHeaderLine;
        try{
            while ((clientHeaderLine = in.readUTF()) != null) { //loop till no conn
                String[] clientHeader = clientHeaderLine.split(",");
                // QUIT and CMD
                if(clientHeader[0].equals("CMD") && clientHeader[1].equals("quit")){
                    System.out.println(this.threadName + " has left.");
                    // break out of while() loop so that the finally() block can be run
                    break;
                }
                else if(clientHeader[0].equals("Auth") && clientHeader[1].equals("I")){ //if receiving a file and caption
                    // System.out.println("here");
                    try {
                        int bytesRead;
                        // record filename and password from  client HEADER
                        String fileName = clientHeader[2];
                        // output stream to write file uploaded from client onto server PC
                        OutputStream output = new FileOutputStream("output/"+fileName);
                        // >> HEADER received from client containing length of byte array to upload
                        long imgSize = in.readLong();
                        long capSize = in.readLong();
                        System.out.println("Decrypting image");
                        byte[] buffer = new byte[(int)imgSize];
                        while (imgSize > 0 && (bytesRead = in.read(buffer, 0, (int) Math.min(buffer.length, imgSize))) != -1) {
//                            output.write(buffer, 0, bytesRead);
                            imgSize -= bytesRead;
                        }
                        byte[] decryptedBuffer = SecurityFunctions.PGPFullDecrypt(buffer,receiverPrivate,senderPublic);
                        output.write(decryptedBuffer, 0, decryptedBuffer.length);
                        output.close();

                        System.out.println("Decrypting caption");
                        byte[] capBuff = new byte[(int)capSize];
                        in.read(capBuff, 0, (int)capSize);
                        byte[] captionDecrypted = SecurityFunctions.PGPFullDecrypt(capBuff,receiverPrivate,senderPublic);
                        String Caption = new String (captionDecrypted);
                        //print file and caption received
                        System.out.println("File received: " + fileName);
                        System.out.println("Image Caption: " + Caption);
                            
                    } catch (IOException ex) {
                        System.out.println("Could not download file...");
                        out.writeUTF("CTR,null,null,null,failed");
                    }
                }
                else if(clientHeader[0].equals("Auth") && clientHeader[1].equals("M")){ //if receiving a message
                    System.out.println("Decrypting message from " + this.threadName);
                    //print message
                    long len = in.readLong();
                    byte[] inputEncrypted = in.readNBytes((int)len);
                    byte[] inputDecrypted = SecurityFunctions.PGPFullDecrypt(inputEncrypted,receiverPrivate,senderPublic);
                    System.out.println(this.threadName + ": " + new String(inputDecrypted));

                }  
                }
        }catch (Exception e) {
        // System.out.println(e);
        }finally {
            try {
                socket.close();
                System.out.println("logging out..");
                System.exit(0);
            } catch (IOException e) {
                System.out.println(e);
            }
        }    
    } 
 
    
    
    public void start(){
        if(read == null){
            read = new Thread (this,threadName);
            read.start();
        }
    }
    
}
