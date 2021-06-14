import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.*;

/**
 *A server where multiple clients can connect. Acts as a shared database.
 */

public class server extends Thread {

    private String[][] docList;
    private ServerSocket ss;

    /**
     * The constructor creates the server socket using port 59090
     */
    private server() {
        try {
            ss = new ServerSocket(59090);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    /**
     *Read docList reads in the current files that are stored in the server, which are written in docList. It stores them in a 2D array.
     * @throws Exception if server cannot find the docList, which in theory should never occur as the server will always have the docList
     */

    private void readDocList() throws Exception
    {
        File f = new File("docList.txt");
        Scanner sc = new Scanner(f);
        int i = 0;
        //count number of lines for text file to assign array dimensions appropriately
        BufferedReader reader = new BufferedReader(new FileReader("docList.txt"));
        int lines = 0;
        while (reader.readLine() != null) lines++;
        reader.close();
        docList = new String[lines][2];
        while(sc.hasNextLine())
        {
            String[] tempArr = sc.nextLine().split(",");
            docList[i][0] = tempArr[0];
            docList[i][1] = tempArr[1];
            i++;
        }
    }

    /**
     *The saveFile method takes in the file that the client wishes to save and stores it in the docList and in files.
     * @param clientSock takes in the client socket
     * @param tempArr is the list of protocols
     * @throws Exception handles the data output stream, ensuring that it has received the client socket and writes to it.
     */

    private void saveFile(Socket clientSock,String[] tempArr) throws Exception {
        DataInputStream dis = new DataInputStream(clientSock.getInputStream());
        FileOutputStream fos = new FileOutputStream(tempArr[0]);

        byte[] buffer = new byte[4096]; // need to send number of bytes from client via UTF

        int read = 0;
        int totalRead = 0;
        int remaining = Integer.parseInt(tempArr[1]);
        while((read = dis.read(buffer, 0, Math.min(buffer.length, remaining))) > 0) {
            totalRead += read;
            remaining -= read;
            fos.write(buffer, 0, read);
        }
        FileWriter fr = new FileWriter("docList.txt", true);
        String tempDoc;
        tempDoc = tempArr[0] + "," + tempArr[3];
        fr.write(tempDoc + "\n");
        fr.close();
    }

    /**
     * The sendFile method takes in the name of the file and password of which the client wishes to download. It reads the docList to ensure the file is there and checks to see if the client has the correct password in order to download the file.
     * @param clientSock takes in the client socket
     * @param tempArr is the list of protocols
     * @throws IOException handles the data output stream, ensuring that it has received the client socket and writes to it.
     */
    private void sendFile(Socket clientSock, String[] tempArr) throws IOException {
        DataOutputStream dos = new DataOutputStream(clientSock.getOutputStream());
        File f = new File(tempArr[0]);

        try{
            FileInputStream FinputS = new FileInputStream(tempArr[0]);
            long fileSize;
            fileSize = f.length();

            String tempPro = "";
            int tempInt = 0;
            tempPro = tempArr[0]+ "," + fileSize;
            String incorrectPass = "incorrectPass,"+0;
            String incorrectFile = "incorrectFile,"+0;
            for(int x = 0; x < docList.length; x++)
            {
                if(docList[x][1].equals(tempArr[1])&& docList[x][0].equals(tempArr[0])||docList[x][1].equals("")&& docList[x][0].equals(tempArr[0])) {
                    tempInt = 1;
                    System.out.println("Sent protocol");
                    break;
                }
                else if(docList[x][0].equals(tempArr[0])){
                    System.out.println("Incorrect password.");
                    tempInt = 2;
                }
                else if(tempInt!=2)
                {
                    tempInt = 3;
                    System.out.println("File does not exist");
                }
            }
            System.out.println("Moving to switch statements");
            switch (tempInt){
                case 1:
                {
                    dos.writeUTF(tempPro);
                    dos.flush();
                    break;
                }
                case 2:
                {
                    dos.writeUTF(incorrectPass);
                    dos.flush();
                    break;
                }
                case 3:
                {
                    dos.writeUTF(incorrectFile);
                    dos.flush();
                    break;
                }
            }

            byte[] buffer = new byte[(int)f.length()];
            while (FinputS.read(buffer) > 0){
                dos.write(buffer);
            }
            dos.close();
            System.out.println("File sent. Check Local Directory\n");
            clientSock.close();
        }
        catch(Exception e){
            //send error message
            String errMess = "incorrectFile,"+0;
            dos.writeUTF(errMess);
        }
    }

    /**
     * This method sends the list of files that are stored and of which the client can see based on their level of access.
     * @param clientSock takes in the client socket.
     * @param tempArr is the list of protocols.
     * @throws IOException handles the data output stream, ensuring that it has received the client socket and writes to it.
     */
    private void sendList(Socket clientSock, String[] tempArr) throws IOException
    {
        DataOutputStream dos = new DataOutputStream(clientSock.getOutputStream());
        File f = new File("docList.txt");

        BufferedReader reader = new BufferedReader(new FileReader("docList.txt"));
        int lines = 0;
        while (reader.readLine() != null) {
            lines++;
            String[] temp = new String[lines];
        }
        reader.close();

        String row;
        String doc = "";
        BufferedReader txtReader = new BufferedReader(new FileReader("docList.txt"));
        while ((row = txtReader.readLine()) != null) {
            String[] data = row.split(",");
            if(data[1].equals(tempArr[3])||data[1].equals(" "))
            {doc += data[0] +"\n";}
        }
        txtReader.close();
        System.out.println(doc);
        dos.writeUTF(doc);
        dos.close();
        System.out.println("List sent. Check Local Directory\n");
        clientSock.close();

    }

    /**
     * The main method starts the program.
     * @param args does not take in anything.
     */

    public static void main(String[] args) {
        server fs = new server();
        fs.start();
        try {
            fs.readDocList();
        }
        catch(Exception e){
            e.printStackTrace();
        }
    }

    /**
     * The run method runs in parallel and calls the various methods based on what action client wishes to perform.
     */
    public void run() {
        System.out.println("Server is now Running...\n");
        while (true) {
            try {
                Socket clientSock = ss.accept();
                DataInputStream dis = new DataInputStream(clientSock.getInputStream());
                String tempPro  = dis.readUTF();
                System.out.println("Received Protocol: "+tempPro);
                String[] tempArr = tempPro.split(",");
                switch(tempArr[2]){
                    case "u":
                        saveFile(clientSock, tempArr);
                        break;
                    case "d":
                        try{
                            sendFile(clientSock, tempArr);
                        }
                        catch(Exception e){
                            e.printStackTrace();
                        }
                        break;
                    case "v":
                        sendList(clientSock, tempArr);
                        break;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}