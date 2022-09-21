import java.io.BufferedOutputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

public class KeyGen {
    private static Scanner sysIn = new Scanner(System.in);     // Scanner object for reading user inputs

    public static void main(String[] args) {
        // write your code here
        BufferedOutputStream xPublicKey = getOutStreamForFile("XPublic.key");
        BufferedOutputStream xPrivateKey = getOutStreamForFile("XPrivate.key");
        BufferedOutputStream yPublicKey = getOutStreamForFile("YPublic.key");
        BufferedOutputStream yPrivateKey = getOutStreamForFile("YPrivate.key");
    }

    private static BufferedOutputStream getOutStreamForFile(String filename){
        try {
            return new BufferedOutputStream(new FileOutputStream(filename));
        } catch (FileNotFoundException e) {
            System.out.println("Error, Could not find file: " + filename);
            e.printStackTrace();
            return null;
        }
    }

    private static void genSymmetricKey(){
        BufferedOutputStream symKeyFile = getOutStreamForFile("symmetric.key");
        System.out.printf("Please input a 16-character string to generate the symmetric key: ");
        String key = "";
        while(key.length() != 16) {
            if(key.length() != 0) {
                System.out.printf("Wrong number of characters, Please input a 16-character string: ");
            }
            key = sysIn.nextLine();  // Read user input
        }
        byte[] symKey = key.getBytes(StandardCharsets.UTF_8);
        try {
            symKeyFile.write(symKey, 0, symKey.length);
            symKeyFile.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

















