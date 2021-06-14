import javax.swing.*;
import java.io.*;
import java.util.Scanner;
import java.lang.*;
import java.net.Socket;

/**
 * A command line client for the date server. Requires the IP address of the
 * server as the sole argument. Exits after printing the response.
 */
public class client {

    private Socket socked;
    private static String fname;
    private static String password;
    private static boolean flag;
    static Scanner sc  = new Scanner(System.in);
    Scanner in;
    final String IP = "localhost";
    //final String IP = "196.24.186.49";
    //final String IP = "196.24.184.223";

    /**
     * The uploadFile method sends the file the client wishes to upload to the server.
     * @param file is the name of the file the client wishe to upload.
     * @throws IOException if client cannot connect to the server IP.
     */
    private void uploadFile(String file) throws IOException {

        try{
            socked = new Socket(IP,59090);
            //socked = new Socket("196.47.201.237", 59090);
        } catch (Exception e){
            e.printStackTrace();
        }

        in = new Scanner(socked.getInputStream());
        fname = JOptionPane.showInputDialog("Enter the filename you wish to upload:");
        File f = new File(fname);

        DataOutputStream DoutputS = new DataOutputStream(socked.getOutputStream());
        FileInputStream FinputS = new FileInputStream(fname);

        //building the protocol
        long fileSize = 0;
        fileSize = f.length();

        password = JOptionPane.showInputDialog("Enter the password for file you wish to upload:");
        if(password.isEmpty()){
            password = " ";
        }
        String tempPro = fname + "," + fileSize +","+"u"+","+password;

        DoutputS.writeUTF(tempPro);//Sends the protocol

        //Read the file into the input stream
        byte[] buffer = new byte[(int)f.length()];
        while (FinputS.read(buffer) > 0){
            DoutputS.write(buffer);
        }

        JOptionPane.showMessageDialog(null,"File sent. Check Directory");
        socked.close();
        //pw.flush();
        //FinputS.close();
        DoutputS.flush();
    }

    /**
     * The downloadFile method send the server the name of the file and password the client wishes to download.
     * @throws IOException if client cannot connect to the server IP.
     */
    private void downloadFile() throws IOException {

        DataOutputStream dos = null;
        DataInputStream dis = null;
        try{
            socked = new Socket(IP,59090);
        } catch (Exception e){
            e.printStackTrace();
        }
        in = new Scanner(socked.getInputStream());
        fname = JOptionPane.showInputDialog("Enter the filename you wish to download:");
        String tempPass = JOptionPane.showInputDialog("Enter the password:");
        if(tempPass.length()==0){
            tempPass = " ";
        }
        String tempPro = fname+","+tempPass+","+"d";

        dos = new DataOutputStream(socked.getOutputStream());
        dos.writeUTF(tempPro); //sends through file name

        dis = new DataInputStream(socked.getInputStream());
        byte[] buffer = new byte[4096]; // need to send number of bytes from client via UTF

        String sfile = dis.readUTF();
        String[] tempArr = sfile.split(",");
        if(tempArr[0].equals("incorrectPass")){
            JOptionPane.showMessageDialog(null,"The password was incorrect");
        }
        else if(tempArr[0].equals("incorrectFile")){
            JOptionPane.showMessageDialog(null,"Error 404: This file was not found");
        }
        else {
            FileOutputStream fos = new FileOutputStream(tempArr[0]);

            File f = new File(tempArr[0]); // attain from client using UTF

            int read = 0;
            int totalRead = 0;
            int remaining = Integer.parseInt(tempArr[1]);
            while ((read = dis.read(buffer, 0, Math.min(buffer.length, remaining))) > 0) {
                totalRead += read;
                remaining -= read;
                fos.write(buffer, 0, read);
            }
            JOptionPane.showMessageDialog(null,"File has successfully downloaded.");
        }
    }

    /**
     * The queryList method requests a list of files available to download from the server.
     * @throws IOException if client cannot connect to the server IP.
     */
    private void queryList()  throws IOException
    {
        DataOutputStream dos = null;
        DataInputStream dis = null;
        try{
            socked = new Socket(IP,59090);
        } catch (Exception e){
            e.printStackTrace();
        }
        in = new Scanner(socked.getInputStream());

        String tempPass = JOptionPane.showInputDialog("Enter the password:");
        if(tempPass.isEmpty()){
            tempPass = " ";
        }
        String tempPro = "0,0,v,"+tempPass;

        dos = new DataOutputStream(socked.getOutputStream());
        dos.writeUTF(tempPro); //sends through file name

        dis = new DataInputStream(socked.getInputStream());
        byte[] buffer = new byte[4096]; // need to send number of bytes from client via UTF

        String sfile = dis.readUTF();
        JOptionPane.showMessageDialog(null,"Files Available for download:"+"\n"+sfile);

    }

    /**
     * The main method runs the client program and receives prompts from the user, who will indicate which action they wish to perform.
     * @param args takes in the action that the client requests.
     */

    public static void main (String[] args){

        flag = true;
        client c = new client();
        while (flag){
            String in = JOptionPane.showInputDialog("Welcome to Jeff's Files. Choose an appropriate option:\nUpload [u]\nDownload [d]\nView list of Files [v]\nQuit [q]");

            switch(in){
                case "u":
                    try {
                        c.uploadFile(fname);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    break;
                case "d":
                    try{
                        c.downloadFile();
                    } catch (IOException e) {
                        e.printStackTrace();
                        //System.out.println("Error 404. File not Found.");
                    }
                    break;
                case "v":
                    try{
                        c.queryList();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    break;
                case "q":
                    flag = false;
                    JOptionPane.showMessageDialog(null,"Thank you for using Jeff's files.");
                    //System.out.println("Thank you for using Jeff's Files!");
                    break;
            }
        }
    }
}