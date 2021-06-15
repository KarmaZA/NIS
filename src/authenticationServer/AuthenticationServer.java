
/*
Haven't done or even started here yet
 */
class AuthenticationServer{

    private static ServerSocket serverSocket;
    private static int portNumber = 45555;

    public static main(String[] args){
        startServer();
    }

    private static void startServer(){
        try{
            serverSocket = new ServerSocket(portNumber);
            System.out.println("Authentication server is listening on port " + portNumber);
        } catch (IOException e){
            e.printStackTrace();
        }
    }

}