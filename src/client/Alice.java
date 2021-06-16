import javax.swing.*;
import java.io.*;
import java.net.Socket;
import java.util.Scanner;
import java.security.*;

class Alice{
    private static Socket socket;
    private String username = "Alice";
    private Scanner scanner = new Scanner(System.in);
    private int portUpload = 45554;

    final String IP = "localhost";

    /**
     *
     * @param args
     */
    public static void main(String[] args){
        try{
            socket = new Socket("localhost", 45554);
            System.out.println("Socket on Alice set up");
        } catch (Exception e){
            System.out.println("I have nothing to connect to :'(");
            e.printStackTrace();
        }

        try {
            String toSend = "This is a test";
            PrintStream out = new PrintStream(socket.getOutputStream());
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            out.println(toSend);
            System.out.println("Sent?");
            toSend = in.readLine();
            System.out.println(toSend);
        } catch (IOException e){
            System.out.println("No message, you've been ghosted");
            e.printStackTrace();
        }
    }

    /**
     *
     * @param file
     * @param caption
     */
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
    }



}