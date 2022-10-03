import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;

public class Receiver {
    private static final Scanner sysIn = new Scanner(System.in);     // Scanner object for reading user inputs
    private static final Integer BUFFER_SIZE = 32 * 1024;

    public static void main(String[] args) {
        System.out.print("Input the name of the message file: ");
        String msgFileName = sysIn.nextLine();  // Read user input
        try {
            PublicKey xPublicK = readPubKeyFromFile("XPublic.key");
            // PrivateKey xPrivateK = readPrivKeyFromFile("XPrivate.key");
            // PublicKey yPublicK = readPubKeyFromFile("YPublic.key");
            //PrivateKey yPrivateK = readPrivKeyFromFile("YPrivate.key");
            byte[] symKey = loadSymmetricKey();
            loadMessage(msgFileName);
        } catch (IOException e) {
            System.out.println("Error finding/reading keys");
            e.printStackTrace();
        }
    }

    private static void loadMessage(String msgFileName) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException {
        BufferedInputStream file = new BufferedInputStream(new FileInputStream(msgFileName));
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Paddin");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
        byte[] buffer = new byte[1024 * 16];
        int numBytesRead;
        while (true) {
            numBytesRead = file.read(buffer, 0, buffer.length);
            if(numBytesRead <= 0) break;
            cipher.doFinal(buffer, 0, numBytesRead);
        }
    }

    private static void step5(String messageOutputFile) throws Exception {
        PublicKey xPublicK = readPubKeyFromFile("XPublic.key");
        BufferedInputStream file = new BufferedInputStream(new FileInputStream("message.ds-msg"));
        BufferedOutputStream mOut = new BufferedOutputStream(new FileOutputStream(messageOutputFile));
        byte[] ds = new byte[128];
        file.read(ds, 0, ds.length);
        String dd = decryptDS(ds, xPublicK);
        byte[] m = new byte[BUFFER_SIZE];
        int numBytesRead;
        do {
            numBytesRead = file.read(m, 0, m.length);
            if(numBytesRead == -1) break;
            mOut.write(m, 0, numBytesRead);
        } while (numBytesRead == BUFFER_SIZE);
        file.close();
    }

    private static String sha256(String fileName) throws NoSuchAlgorithmException, IOException {
        BufferedInputStream file = new BufferedInputStream(new FileInputStream(fileName));
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        DigestInputStream in = new DigestInputStream(file, md);
        byte[] buffer = new byte[BUFFER_SIZE];
        int numBytesRead;
        do {
            numBytesRead = in.read(buffer, 0, buffer.length);
        } while (numBytesRead > 0);
        md = in.getMessageDigest();
        in.close();

        byte[] hash = md.digest();
        return new String(hash, StandardCharsets.UTF_8);
    }

    public static String decryptDS(byte[] input, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        SecureRandom random = new SecureRandom();

        /* first, encryption & decryption via the paired keys */
        cipher.init(Cipher.DECRYPT_MODE, key, random);

        byte[] plainText = cipher.doFinal(input);
        System.out.println("plainText (" + plainText.length +" bytes): " + new String(plainText) + "\n");
        return new String(plainText, StandardCharsets.UTF_8);
    }

    private static void printHashFromString(String hash){
        byte[] h = hash.getBytes(StandardCharsets.UTF_8);
        System.out.println("digital digest (hash value):");
        for (int k=0; k<h.length; k++) {
            System.out.format("%2X ", h[k]) ;
            if (k + 1 % 16 == 0) System.out.println("");
        }
        System.out.println("");

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
}
