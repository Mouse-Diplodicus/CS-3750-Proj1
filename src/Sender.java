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
    // Scanner for user input
    private static Scanner sysIn = new Scanner(System.in);     // Scanner object for reading user inputs
    // Buffer for hashing large files
    private static int BUFFER_SIZE = 32 * 1024;
    // IV for AES encryption
    private static String IV = "HJDSLBWERAYTIZQP";
    private static PrivateKey xPrivateK;
    private static byte[] symKey;


    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException,
        NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, Exception {
        
        // Step 3: Read user input
        System.out.print("Input the name of the message file: ");
        String fileName = sysIn.nextLine();
        try {
            // Step 2: Read information on keys
            xPrivateK = readPrivKeyFromFile("XPrivate.key");
            symKey = loadSymmetricKey();

            // Step 4: Calculate SHA256
            byte[] hash = getSHA(fileName);
            // Step 5: Calculate RSA encryption of SHA256
            RSAencrypt(hash, fileName);
            // Step 6: Calculate 
            AESEncrypt();
        } catch (IOException e) {
            System.out.println("Error finding/reading keys");
            e.printStackTrace();
        }
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
        file.close();

        byte[] hash = md.digest();

        System.out.println("Do you want to invert the first byte in SHA256(M)? (Y or N)");
        String answer = sysIn.nextLine();
        // TO DO: While !validIn
        if (answer.toLowerCase().toCharArray()[0] == 'y') {
            // If answer is yes, replace first byte with bitwise its inverted value
            hash[0] = (byte) ~hash[0];
        }

        System.out.println("Digital Digest (SHA256(M)):");
        printHash(hash);

        // Save hash to file message.dd
        BufferedOutputStream shaMessageFile = new BufferedOutputStream(new FileOutputStream("message.dd"));

        shaMessageFile.write(hash, 0, hash.length);
        shaMessageFile.close();

        return hash;
    }

    // Step 5: Calculate RSA Encryption
    public static void RSAencrypt(byte[] hash, String messageName) throws NoSuchAlgorithmException, BadPaddingException,
            NoSuchPaddingException, IOException, InvalidKeyException, IllegalBlockSizeException{
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, xPrivateK);
        byte[] cipherText = cipher.doFinal(hash);

        // System.out.println("CipherText block size is "
        // +  cipherText.length + " bytes");      //32 -> 128 bytes

        System.out.println("Cipher Text (RSA-En Kx– (SHA256(M))):");
        printHash(cipherText);

        BufferedOutputStream RSAencryption = new BufferedOutputStream(new FileOutputStream("message.ds-msg"));
        BufferedInputStream message = new BufferedInputStream(new FileInputStream(messageName));

        // write CipherText to file (RSA-En Kx– (SHA256(M)))
        RSAencryption.write(cipherText, 0, cipherText.length);

        // write Message to file M
        int numBytesRead;
        byte[] buffer = new byte[BUFFER_SIZE];
        do {
            numBytesRead = message.read(buffer, 0, BUFFER_SIZE);
            RSAencryption.write(buffer, 0, numBytesRead);
        } while (numBytesRead == BUFFER_SIZE);
        message.close();
        RSAencryption.close();
    }

    // Step 6: Calulate AES Encryption
    public static void AESEncrypt() throws Exception {
        BufferedInputStream file = new BufferedInputStream(new FileInputStream("message.ds-msg"));
        BufferedOutputStream AESencryption = new BufferedOutputStream(new FileOutputStream("message.aescipher"));

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
        SecretKeySpec key = new SecretKeySpec(symKey, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));

        // Read 16 bytes at a time and write to file message.aescipher
        byte[] buffer = new byte[BUFFER_SIZE];
        int numBytesRead;
        do {
            numBytesRead = file.read(buffer, 0, buffer.length);
            AESencryption.write(cipher.doFinal(buffer, 0, numBytesRead));
        } while (numBytesRead == BUFFER_SIZE);
        AESencryption.close();
        file.close();
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
        System.out.println("Symmetric Key: " + new String(symKey, StandardCharsets.UTF_8) + "\n");
        return symKey;
    }

    private static void printHash(byte[] hash){
        for (int k = 0; k<hash.length; k++) {
            String out = String.format("%2X", hash[k]).replace(' ', '0');
            System.out.print(out + " ") ;
            if ((k + 1) % 16 == 0) System.out.println("");
        }
        System.out.println("");
    }
}