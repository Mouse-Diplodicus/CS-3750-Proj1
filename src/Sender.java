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
import java.security.InvalidKeyException;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.util.Scanner;
import java.io.IOException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.util.Arrays;
import java.io.FileNotFoundException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.NoSuchPaddingException;


public class Sender{
    // Scanner for user inut
    private static final Scanner sysIn = new Scanner(System.in);     // Scanner object for reading user inputs
    // Buffer for hashing large files
    private static int BUFFER_SIZE = 32 * 1024;
    // IV for AES encryption
    static String IV = "AAAAAAAAAAAAAAAA";


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

    public static String getUserInput() throws FileNotFoundException {
        // Step 3: Get user input
        System.out.print("Input the name of the message file: ");
        // Read user input
        String fileName = sysIn.next();
        return fileName;
    }

    /** Create method to check if input is valid
    private static boolean isValid(String answer) {
        if (answer == "Y" || answer == "N") {
            return true;
        }
        else return false;
    } */

    // Step 4: Calculate hash value
    public static byte[] getSHA(String[] args) throws FileNotFoundException, NoSuchAlgorithmException,
    IOException {
        String fileName = getUserInput();
        BufferedInputStream file = new BufferedInputStream(new FileInputStream(fileName));
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
        for (int k=0, j=0; k < hash.length; k++, j++) {
          System.out.format("%2X ", hash[k]) ;
          if (j >= 15) {
            System.out.println("");
            j=-1;
          }
          System.out.println("The SHA(M) in Hexidecimal bytes: " + hash);

        Scanner invert = new Scanner(System.in);
        System.out.println("Do you want to invert the first byte in SHA256(M)? (Y or N)");
        String answer = invert.nextLine();
        
        // If answer is valid continue
        // if (isValid(answer)) 
        if (answer == "Y"){
            for (int index = 0; index < hash.length; index++){
                // If answer is yes, replace firt byte with bitwise its inverted value
                // hash[0] = hash[~0 & 0xff];
                int x = hash[0];
                x = ~x & 0xff;
                hash[0] = hash[x];
                System.out.println("You answered: " + answer + "The first bit is now: " + hash[0]);
            }
        }
        if (answer == "N"){
            // If answer is "N" no change
            System.out.println("You answered: " + answer + ". There is no change to the first bit.");
        }
        else {
            System.out.println("That was not a valid input, please try again.");
            answer = invert.nextLine();
        }
        invert.close();

        // Save hash to file message.dd
        BufferedOutputStream shaMessageFile = new BufferedOutputStream(new FileOutputStream("message.dd"));
        
        shaMessageFile.write(hash, 0, hash.length);
        shaMessageFile.close();
        // Display hash
        System.out.println("The hash is: " + Arrays.toString(hash));
        }
        return hash;
    }
    
    // Step 5: Calculate RSA Encryption
    public static byte[] RSAencrypt(String data, String privateString,  byte[] hash) throws NoSuchAlgorithmException, InvalidKeySpecException,
    BadPaddingException, NoSuchPaddingException, IOException, InvalidKeyException, IllegalBlockSizeException{
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, readPrivKeyFromFile("XPrivate.key"));
        byte[] cipherText = cipher.doFinal(hash);
        //32 -> 128 bytes
        System.out.println("CipherText block size is " 
        +  cipherText.length + " bytes");

        //Convert byte array to hex value
        for (int ind=0, j=0; ind < cipherText.length; ind++, j++) {
            System.out.format("%02X ", cipherText[ind]);
            String cipherHash = String.format("%02x", cipherText[ind]);
            if (j >= 15) {
                System.out.println("");
                j=-1;
                }
            }
            System.out.println("");
        
        BufferedOutputStream RSAencryption = new BufferedOutputStream(new FileOutputStream("message.ds-msg"));
        // TO DO: How to pass cipherHash to file
        //###########################################################################################################
        // Save hex value of cipher text to message.ds-msg file
        RSAencryption.write(cipherText, 0, cipherText.length);
        RSAencryption.close();

        return cipherText; // Not needed?
    }
    // Step 6: Calulate AES Encryption
    public static byte[] encrypt() throws Exception {
        
        // Calulate AES Encryption using sym key KXY by reading file "message-ds.msg"
        // (RSA-En Kx– (SHA256 (M)) || M) 

        // Variable to read 16 bytes
        int length = 16;
        byte[] readBytes = new byte[length];
        // Load Symmetric key
        byte[] symKey = loadSymmetricKey(); 

        // WHEN/HOW TO USE SYMMETRIC KEY??

        /** If the length of the last peice is less than that of 16 bytes, it needs to be 
         * placed in a byte array whose array size is the length of the last piece is the
         * length of the last piece before being encrypted */

        FileInputStream message = new FileInputStream("message.ds-msg");
        message.read("message.ds-msg");

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
        SecretKeySpec key = new SecretKeySpec(message.getBytes("UTF-8"), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key,new IvParameterSpec(IV.getBytes("UTF-8")));

        // Save resulting blocks of AES ciphertext into a file named "message.aescipher"
        BufferedOutputStream AESencryption = new BufferedOutputStream(new FileOutputStream("message.aescipher"));
        AESencryption.write(cipherText, 0, cipherText.length);
        AESencryption.close();

        return cipher.doFinal(message.getBytes("UTF-8"));
    }
}