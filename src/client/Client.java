
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

import java.io.DataInputStream;
import java.io.DataOutputStream;

import java.io.File;

import java.io.FileInputStream;
import java.io.BufferedInputStream;
import java.util.Scanner;
import java.nio.ByteBuffer;

public class Client {

    public static void main(String[] args) throws Exception {

        // scanner used for all client input
        Scanner scanner = new Scanner(System.in);

        // client enters IP address to connect to server
        // System.out.println("Enter: <IP>");
        // String clientIP = scanner.nextLine();

        System.out.println("Connecting...");

        // connect to server on designated IP address and port number 59897
        try (Socket socket = new Socket("localhost", 59897)) {

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
