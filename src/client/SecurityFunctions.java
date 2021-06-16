import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.SecureRandom;
import java.util.zip.GZIPOutputStream;

import org.bouncycastle.*;

public class SecurityFunctions {
    public static void main(String[] args) {

    }
    public static String encrypt(String message, Key publickey, Key privatekey, Key sharedkey){
//        byte[] data = new byte[AES_NIVBITS/8]; //nope
//        new SecureRandom().nextBytes();

        return "";
    }
    public static String decrypt (String message,Key publickey, Key privatekey, Key sharedkey){
        return "";
    }
    public static String hash (String message){
        return "";
    }

    public static String compress(String message) throws IOException { //assuming message is not null
        ByteArrayOutputStream out = new ByteArrayOutputStream(); //the output stream
        GZIPOutputStream gzip = new GZIPOutputStream(out); //another stream
        gzip.write(message.getBytes()); //write the message to the output stream
        gzip.close(); //so it is no longer open
        return out.toString("ISO-8859-1");
    }
}
