import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.MessageDigest;
import java.security.DigestInputStream;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.util.Scanner;

public class Sender {
    private static final Scanner sysIn = new Scanner(System.in);     // Scanner object for reading user inputs
    
    public static void main(String[] args) {
        try {
            PublicKey xPublicK = readPubKeyFromFile("XPublic.key");
            PrivateKey xPrivateK = readPrivKeyFromFile("XPrivate.key");
            PublicKey yPublicK = readPubKeyFromFile("YPublic.key");
            PrivateKey yPrivateK = readPrivKeyFromFile("YPrivate.key");
            byte[] symKey = loadSymmetricKey();
        } catch (IOException e) {
            System.out.println("Error finding/reading keys");
            e.printStackTrace();
        }
    }


    private static void loadMessage(){
        System.out.print("Input the name of the message file: ");
        String msgFileName = sysIn.nextLine();  // Read user input
    }

    //read public key parameters from a file and generate the public key
    private static PublicKey readPubKeyFromFile(String keyFileName)
            throws IOException {
        try(ObjectInputStream oin = new ObjectInputStream(new FileInputStream(keyFileName))) {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();
            System.out.println("Read from " + keyFileName + ":\n    modulus = " +
                    m.toString() + "\n    exponent = " + e.toString() + "\n");

            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PublicKey key = factory.generatePublic(keySpec);
            return key;
        } catch (Exception e) {
            throw new RuntimeException("Spurious serialisation error", e);
        }
    }

    //read private key parameters from a file and generate the private key
    private static PrivateKey readPrivKeyFromFile(String keyFileName)
            throws IOException {
        try(ObjectInputStream oin = new ObjectInputStream(new FileInputStream(keyFileName))) {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();
            System.out.println("Read from " + keyFileName + ":\n    modulus = " +
                    m.toString() + "\n    exponent = " + e.toString() + "\n");

            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PrivateKey key = factory.generatePrivate(keySpec);
            return key;
        } catch (Exception e) {
            throw new RuntimeException("Spurious serialisation error", e);
        }
    }

    // load Symmetric key from user input and write it to a file ASDFQWERTYPRfVIB
    private static byte[] loadSymmetricKey() throws IOException {
        byte[] symKey = new byte[16];
        BufferedInputStream symKeyFile = new BufferedInputStream(new FileInputStream("symmetric.key"));
        symKeyFile.read(symKey, 0, 16);
        symKeyFile.close();
        System.out.println(new String(symKey, StandardCharsets.UTF_8));
        return symKey;
    }



    /** Calculate the RSA Encryption of SHA256(M) using Kx – (Question: how many bytes is the cyphertext?), SAVE this RSA 
     * cyphertext  (the  digital  signature  of  M),  into  a  file  named  “message.ds-msg”,  and  DISPLAY  it  in  Hexadecimal  bytes.  
     * APPEND the message M read from the file specified in Step 3 to the file “message.ds-msg” piece by piece. */
    
    // Get SHA-256 to calculate message digest of an input returned as a byte array
    /**   
    private static byte[] SHAHash(String input) throws NoSuchAlgorithmException{
        MessageDigest msg = MessageDigest.getInstance("SHA-256");
        return msg.digest(input.getBytes(StandardCharsets.UTF_8));
    }

    // Convert message digest to hex
    public static String toHexString(byte[] hash) throws IOException {
        BigInteger num = new BigInteger(1, hash);
        StringBuilder hex = new StringBuilder(num.toString(16));

        while (hex.length() < 64){
            // Append 0's
            hex.insert(0, '0');
        }
        return hex.toString();

        System.out.println("The SHA(M) in Hexidecimal bytes: " + toHexString(getSHA(keyFileName)));

        BufferedOutputStream shaMessageFile = new BufferedOutputStream(new FileOutputStream("message.dd"));
        
        shaMessageFile.writeBytes(hex, 0, hex.length);
        shaMessageFile.close();
        }
    } 
    */

    private static int BUFFER_SIZE = 32 * 1024;

    public static String md(String keyFileName) throws Exception {
        BufferedInputStream file = new BufferedInputStream(new FileInputStream(keyFileName));
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        DigestInputStream in = new DigestInputStream(file, md);
        int i;
        byte[] buffer = new byte[BUFFER_SIZE];
        do {
          i = in.read(buffer, 0, BUFFER_SIZE);
        } while (i == BUFFER_SIZE);
        md = in.getMessageDigest();
        in.close();
        byte[] hash = md.digest();
        System.out.println("digit digest (hash value):");
        for (int k=0, j=0; k<hash.length; k++, j++) {
          System.out.format("%2X ", hash[k]) ;
          if (j >= 15) {
            System.out.println("");
            j=-1;
          }
        }
        System.out.println("");    
        System.out.println("The SHA(M) in Hexidecimal bytes: " + hash);

        Scanner invert = new Scanner(System.in);
        System.out.println("Do you want to invert the first byte in SHA256(M)? (Y or N)");
        String answer = invert.nextLine();
        // TODO: Add while loop
        if (answer == "Y"){
            for (int index = 0; index < hash.length; index++){
                // If answer is yes, replace firt byte with bitwise its inverted value
                int x = hash[0];
                x = ~x & 0xff;
                hash[0] = hash[x];
                System.out.println("You answered: " + answer + "The first bit is: " + hash[0]);
            }
        }
        if (answer == "N"){
            // If answer is "N" no change
            hash[0] = hash[0];
            System.out.println("You answered: " + answer);
        }
        else {
            System.out.println("That was not a valid input, please try again.")
            answer = invert.nextLine();
        }
        invert.close();

        // Save hash to file message.dd
        BufferedOutputStream shaMessageFile = new BufferedOutputStream(new FileOutputStream("message.dd"));
        
        shaMessageFile.write(hash, 0, hash.length);
        shaMessageFile.close();
        // Display hash
        System.out.println("The hash is: " + hash);
        return new String(hash);
      }

    /** 
    // Calculate the RSA encryption of SHA256 using Kx-
    cipher.init(Cipher.ENCRYPT_MODE, xPrivateK);
    // Return X's private key
    public PrivateKey getPrivateKey() {
        return privateKey;
    }
    */

}
