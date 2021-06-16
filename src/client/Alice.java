import javax.swing.*;
import java.io.*;
import java.net.Socket;
import java.util.Scanner;

class Alice{
    private String username = "Alice";
    private Scanner scanner = new Scanner(System.in);
    private static int portUpload = 45554;

    final String IP = "localhost";

    /**
     *
     * @param args
     */
    public static void main(String[] args){
        //Socket socket = Connect(portUpload);
        if(AuthenticateCommunication(Connect(portUpload))){
            //Write code for communication here
        } else {
            System.out.println("Authentication failed");
        }


    }

    /**
     This method will return true or false when authenticating communication with a user on a given port

     For the sake of this prac e're only connecting to one client port and not using threads
     */
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
            toSend = inBob.readLine();
            System.out.println("The session key from Bob is " + toSend);

            return true;
        } catch (IOException e){
            System.out.println("No message, you've been ghosted");
            e.printStackTrace();
            return false;
        }
    }

    private static Socket Connect(int portConnectionNumber){
        try{
            Socket socket = new Socket("localhost", portConnectionNumber);
            System.out.println("Socket on Alice set up");
            return socket;
        } catch (Exception e){
            System.out.println("I have nothing to connect to :'(");
            e.printStackTrace();
        }
        return null;
    }
}




/**
 *
 * //@param file
 * //@param caption
 /
 private void SendFile(String file, String caption) throws IOException{
 try{
 socket = new Socket(IP, portUpload);
 System.out.println("Socket on Alice set up");
 } catch (Exception e){
 e.printStackTrace();
 }

 String toSend = "This is a test";
 PrintStream out = new PrintStream( socket.getOutputStream() );
 BufferedReader in = new BufferedReader( new InputStreamReader( socket.getInputStream() ) );
 out.println(toSend);
 System.out.println("Sent?");
 // Follow the HTTP protocol of GET <path> HTTP/1.0 followed by an empty line
 //out.println( "GET " + path + " HTTP/1.0" );
 //out.println();

 // Read data from the server until we finish reading the document
 //String line = in.readLine();
 //while( line != null )
 //{
 // System.out.println( line );
 // line = in.readLine();
 // }


 // Close our streams
 in.close();
 out.close();
 socket.close();

 /*Scanner in = new Scanner(socket.getInputStream());
 String fileName = JOptionPane.showInputDialog("Enter the filename you wish to upload:");
 File f = new File(file);

 try{
 DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());
 try{
 FileInputStream fileInputStream = new FileInputStream(fileName);
 //building the protocol
 long fileSize = 0;
 fileSize = f.length();

 String tempPro = fileName + "," + fileSize;// +","+"u"+","+password;

 dataOutputStream.writeUTF(tempPro);//Sends the protocol

 //Read the file into the input stream
 byte[] buffer = new byte[(int)f.length()];
 while (fileInputStream.read(buffer) > 0){
 dataOutputStream.write(buffer);
 }

 JOptionPane.showMessageDialog(null,"File sent. Check Directory");
 socket.close();

 dataOutputStream.flush();
 } catch (FileNotFoundException e){
 e.printStackTrace();
 }
 } catch (IOException e){
 e.printStackTrace();
 }*/