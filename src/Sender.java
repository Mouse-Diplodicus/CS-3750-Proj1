import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;

public class Sender {

    public static void main(String[] args) {
        // write your code here
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
}
