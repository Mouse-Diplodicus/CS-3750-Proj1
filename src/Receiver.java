import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
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
    private static String IV = "HJDSLBWERAYTIZQP";
    private static PublicKey xPublicK;
    private static byte[] symKey;

    public void main(String[] args) {
        System.out.print("Input the name of the message file: ");
        String msgFileName = sysIn.nextLine();  // Read user input
        try {
            this.xPublicK = readPubKeyFromFile("XPublic.key");
            this.symKey = loadSymmetricKey();
            loadAndAESDecrypt("message.aescipher");
            String ddDecrypted = rsaDecrypt(msgFileName);
            String ddCalculated = sha256(msgFileName);
            if (ddDecrypted == ddCalculated) {
                System.out.print("Authentication Passed");
            } else {
                System.out.print("Authentication Failed");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void loadAndAESDecrypt(String msgFileName) throws Exception {
        BufferedInputStream file = new BufferedInputStream(new FileInputStream(msgFileName));
        BufferedOutputStream outFile = new BufferedOutputStream(new FileOutputStream("message.ds-msg"));
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Paddin");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(this.symKey, "AES"),
                new IvParameterSpec(IV.getBytes("UTF-8")));
        byte[] buffer = new byte[BUFFER_SIZE];
        int numBytesRead;
        while (true) {
            numBytesRead = file.read(buffer, 0, buffer.length);
            if(numBytesRead <= 0) break;
            if(numBytesRead == BUFFER_SIZE) {
                outFile.write(cipher.doFinal(buffer, 0, numBytesRead));
            } else {
                byte[] smallBuffer = new byte[numBytesRead];
                System.arraycopy(buffer, 0, smallBuffer, 0, numBytesRead);
                outFile.write(cipher.doFinal(smallBuffer, 0, numBytesRead));
            }
        }
        file.close();
        outFile.close();
    }

    private String rsaDecrypt(String messageOutputFile) throws Exception {
        BufferedInputStream file = new BufferedInputStream(new FileInputStream("message.ds-msg"));
        BufferedOutputStream mOut = new BufferedOutputStream(new FileOutputStream(messageOutputFile));
        BufferedOutputStream ddOut = new BufferedOutputStream(new FileOutputStream("message.dd"));

        byte[] ds = new byte[128];
        file.read(ds, 0, ds.length);

        byte[] m = new byte[BUFFER_SIZE];
        int numBytesRead;
        do {
            numBytesRead = file.read(m, 0, m.length);
            if(numBytesRead == -1) break;
            mOut.write(m, 0, numBytesRead);
        } while (numBytesRead == BUFFER_SIZE);

        byte[] dd = decryptDS(ds, this.xPublicK);
        printHash(dd);
        ddOut.write(dd);

        file.close();
        mOut.close();
        ddOut.close();

        return new String(dd, StandardCharsets.UTF_8);
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
        file.close();

        byte[] hash = md.digest();
        return new String(hash, StandardCharsets.UTF_8);
    }

    public static byte[] decryptDS(byte[] input, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        cipher.init(Cipher.DECRYPT_MODE, key);

        return cipher.doFinal(input);
    }

    private static void printHash(byte[] hash){
        System.out.println("digital digest (hash value):");
        for (int k=0; k<hash.length; k++) {
            System.out.format("%2X ", hash[k]) ;
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
