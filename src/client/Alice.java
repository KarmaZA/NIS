import javax.swing.*;
import java.io.*;
import java.net.Socket;
import java.util.Scanner;

class Alice{
    private Socket socket;
    private String username = "Alice";
    private Scanner scanner = new Scanner(System.in);
    private int portUpload = 45554;

    final String IP = "localhost";

    /**
     *
     * @param args
     */
    public static void main(String[] args){

    }

    /**
     *
     * @param file
     * @param caption
     */
    private void SendFile(String file, String caption) throws IOException{
        try{
            socket = new Socket(IP, portUpload);
        } catch (Exception e){
            e.printStackTrace();
        }

        Scanner in = new Scanner(socket.getInputStream());
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
        }



    }
}