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
    static String IV = "HJDSLBWERAYTIZQP";
    private static PublicKey xPublicK;
    private static PublicKey xPrivateK;


    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException,
        NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, Exception {
        
        // Step 3: Read user input
        System.out.print("Input the name of the message file: ");
        String fileName = sysIn.next();
        try {
            // Step 1: Read information on keys 
            System.out.println("Modulus and exponents from XPublic and XPrivate Keys");
            readPubKeyFromFile("XPublic.key");
            readPrivKeyFromFile("XPrivate.key");
            System.out.println(loadSymmetricKey());

            // Step 4: Calculate SHA256
            byte[] hash = getSHA(fileName);
            getSHA(fileName);
            // Step 5: Calculate RSA encryption of SHA256
            String RSAstring = RSAencrypt(hash);
            RSAencrypt(hash);
            // Step 6: Calculate 
            encrypt(RSAstring);
            
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

    private static void printHashFromString(byte[] hash){
        System.out.println("digital digest (hash value):");
        for (int k=0; k<hash.length; k++) {
            System.out.format("%2X ", hash[k]) ;
            if (k + 1 % 16 == 0) System.out.println("");
        }
        System.out.println("");

    }

    // Step 4: Calculate hash value
    public static byte[] getSHA(String msgFileName) throws FileNotFoundException, NoSuchAlgorithmException,
    IOException {
        BufferedInputStream file = new BufferedInputStream(new FileInputStream(msgFileName));
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

        printHashFromString(hash);
        System.out.println("digit digest (hash value):");
        for (int k=0, j=0; k < hash.length; k++, j++) {
          System.out.format("%2X ", hash[k]) ;
          if (j >= 15) {
            System.out.println("");
            j=-1;
          }
          System.out.println("The SHA(M) in Hexidecimal bytes: " + hash);

        System.out.println("Do you want to invert the first byte in SHA256(M)? (Y or N)");
        String answer = sysIn.nextLine();
        // TO DO: While !validIn
        if (answer == "Y"){
                // If answer is yes, replace firt byte with bitwise its inverted valu
                hash[0] = (byte) ~hash[0];
                System.out.println("You answered: " + answer + "The first bit is now: " + hash[0]);
            }
        }

        // Save hash to file message.dd
        BufferedOutputStream shaMessageFile = new BufferedOutputStream(new FileOutputStream("message.dd"));
        
        shaMessageFile.write(hash, 0, hash.length);
        shaMessageFile.close();
        // Display hash
        System.out.println("The hash is: " + Arrays.toString(hash));

        return hash;
    }
    
    // Step 5: Calculate RSA Encryption
    public static String RSAencrypt(byte[] hash) throws NoSuchAlgorithmException, InvalidKeySpecException,
    BadPaddingException, NoSuchPaddingException, IOException, InvalidKeyException, IllegalBlockSizeException{
        // byte [] hash = getSHA();
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, readPrivKeyFromFile("XPrivate.key"));
        byte[] cipherText = cipher.doFinal(hash);
        //32 -> 128 bytes
        System.out.println("CipherText block size is " 
        +  cipherText.length + " bytes");

        System.out.println("The hash is: " + Arrays.toString(hash));
        //Convert byte array to hex value
        for (int ind=0, j=0; ind < cipherText.length; ind++, j++) {
            System.out.format("%02X ", cipherText[ind]);
            if (j >= 15) {
                System.out.println("");
                j=-1;
                }
            }
            System.out.println("");
    
        BufferedOutputStream RSAencryption = new BufferedOutputStream(new FileOutputStream("message.ds-msg"));

        RSAencryption.write(hash, 0, hash.length);
        RSAencryption.write(cipherText, 0, cipherText.length);
        RSAencryption.close();

        return new String(cipherText, StandardCharsets.UTF_8);
    }

    // Step 6: Calulate AES Encryption
    public static byte[] encrypt(String RSAstring) throws Exception {

        // String RSAstring = RSAencrypt();

        // Load Symmetric key
        byte[] symKey = loadSymmetricKey(); 

        FileInputStream file = new FileInputStream("message.ds-msg");
        BufferedOutputStream AESencryption = new BufferedOutputStream(new FileOutputStream("message.aescipher"));

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
        SecretKeySpec key = new SecretKeySpec(symKey, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));

        // Read 16 bytes at a time and write to file message.aescipher
        byte[] buffer = new byte[BUFFER_SIZE];
        int numBytesRead;
        while (true) {
            numBytesRead = file.read(buffer, 0, buffer.length);
            if(numBytesRead <= 0) break;
            if(numBytesRead == BUFFER_SIZE) {
                AESencryption.write(cipher.doFinal(buffer, 0, numBytesRead));
            } else {
                byte[] smallBuffer = new byte[numBytesRead];
                System.arraycopy(buffer, 0, smallBuffer, 0, numBytesRead);
                AESencryption.write(cipher.doFinal(smallBuffer, 0, numBytesRead));
            }
        }
        System.out.println("Final encrypted file: " + AESencryption);

        AESencryption.close();
        file.close();
        return cipher.doFinal(RSAstring.getBytes("UTF-8"));
    }
}