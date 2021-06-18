import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.Hashtable;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.OutputStream;
import java.io.FileOutputStream;
import java.util.Scanner;


public class Server {

    // server password (client must authenticate before accessing server)
    final private static String password = "1234";

    // hash table to store all file names and passwords
    // private static Hashtable<String,String> fileNames = new Hashtable<String,String>();
    //key is name, the other thing is the password
    public static void main(String[] args) throws Exception {

        // create a server socket on localhost IP address and port number 59897
        try (ServerSocket listener = new ServerSocket(59897)) {
            System.out.println("You are online, waiting for Alice to connect");
            // thread pool to limit the number of clients running simultaneously
            ExecutorService pool = Executors.newFixedThreadPool(20);
            // server socket continuosly listens for client connections
            while (true) {
                // when a client connects to server socket, the new socket is run in a seperate thread
                pool.execute(new Handler(listener.accept()));
            }
        }
    }

    private static class Handler implements Runnable {

        private Socket socket;
        Handler(Socket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            // client connection successful
            System.out.println("Verifying Alice on: " + socket);
            try {
                // scanner used for all client input
                Scanner scanner = new Scanner(System.in);
                // input and output streams to read and write from client
                DataInputStream in = new DataInputStream(socket.getInputStream());
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                // initialise client HEADER that will be received
                String clientAuthHeaderLine;
                while ((clientAuthHeaderLine = in.readUTF()) != null) { //read in from Alice
                    String[] clientAuthHeader = clientAuthHeaderLine.split(",");
                    // check authentication before proceeding
                    if(clientAuthHeader[0].equals("CMD") && clientAuthHeader[1].equals("START")){

                        if(clientAuthHeader[2].equals(Server.password)){
                            System.out.println("Password Correct: " + socket);
                            out.writeUTF("CMD,null,null,null,success");
                            Client.done = false;
                            break;
                        }
                        else{
                            System.out.println("Password Incorrect: " + socket);
                            out.writeUTF("CMD,null,null,null,fail");
                        }
                    }
                }    

                //threads for sending and receiving messages/images
                readThread read = new readThread("Alice", socket, in, out);
                writeThread write = new writeThread("Alice", scanner, socket, in, out);
                    read.start();
                    write.start();

            } catch (Exception e) {
                System.out.println("Bye Bob");
            } 
        }
    }
}