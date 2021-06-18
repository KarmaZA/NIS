import java.io.IOException;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.io.OutputStream;
import java.io.FileOutputStream;

public class readThread implements Runnable {

    private Thread read;
    private String threadName;
    private DataInputStream in;
    private DataOutputStream out;
    private Socket socket;
    

    public readThread(String threadName, Socket socket, DataInputStream in, DataOutputStream out){
        this.threadName = threadName;
        this.socket  = socket;
        this.in = in;
        this.out = out;
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
                else if(clientHeader[0].equals("Auth") && clientHeader[1].equals("I")){
                    // System.out.println("here");
                    try {
                        int bytesRead;

                        // record filename and password from  client HEADER
                        String fileName = clientHeader[2];
                        // outputstream to write file uploaded from client onto server PC
                        OutputStream output = new FileOutputStream("output/"+fileName);
                        // >> HEADER received from client containing length of byte array to upload
                        long size = in.readLong();
                        long capSize = in.readLong();
                        // System.out.println(capSize);
                        byte[] buffer = new byte[(int)size];
                        while (size > 0 && (bytesRead = in.read(buffer, 0, (int) Math.min(buffer.length, size))) != -1) {
                            output.write(buffer, 0, bytesRead);
                            size -= bytesRead;
                        }
                        output.close();
                        byte[] capBuff = new byte[(int)capSize];
                        in.read(capBuff, 0, (int)capSize);
                        String Caption = new String (capBuff);  
                        //print file and caption received
                        System.out.println("File received: " + fileName);
                        System.out.println("Image Caption: " + Caption);
                            
                    } catch (IOException ex) {
                        System.out.println("Could not upload file...");
                        out.writeUTF("CTR,null,null,null,failed");
                    }
                }
                else if(clientHeader[0].equals("Auth") && clientHeader[1].equals("M")){
                    //print message
                    System.out.print(this.threadName + ": ");
                    System.out.println(in.readUTF());                       
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
