import java.io.IOException;
import java.net.ServerSocket;

class Bob{
    private static ServerSocket serverSocket;
    private String IP = "localhost";
    private static int portNumber = 45554;


    public static void main(String[] args){
        startServer();
    }

    private static void startServer(){
        try{
            serverSocket = new ServerSocket(portNumber);
        } catch (IOException e){

        }
    }
}