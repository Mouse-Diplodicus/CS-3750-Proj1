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
    private static Scanner sysIn = new Scanner(System.in);     // Scanner object for reading user inputs
    private static final Integer BUFFER_SIZE = 32 * 1024;
    private static String IV = "HJDSLBWERAYTIZQP";
    private static PublicKey xPublicK;
    private static byte[] symKey;

    public static void main(String[] args) {
        System.out.print("Input the name of the message file: ");
        String msgFileName = sysIn.nextLine();  // Read user input
        try {
            xPublicK = readPubKeyFromFile("XPublic.key");
            symKey = loadSymmetricKey();
            loadAndAESDecrypt();
            String ddCalculated = getSHA(msgFileName);
            String ddDecrypted = rsaDecrypt(msgFileName);
            System.out.println("ddCalculated: " + ddCalculated);
            System.out.println("ddDecrypted:  " + ddDecrypted);
            if (ddCalculated == ddDecrypted) {
                System.out.println("Authentication Passed");
            } else {
                System.out.println("Authentication Failed");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void loadAndAESDecrypt() throws Exception {
        BufferedInputStream file = new BufferedInputStream(new FileInputStream("message.aescipher"));
        BufferedOutputStream outFile = new BufferedOutputStream(new FileOutputStream("message.ds-msg"));
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(symKey, "AES"),
                new IvParameterSpec(IV.getBytes("UTF-8")));
        byte[] buffer = new byte[BUFFER_SIZE];
        int numBytesRead;
        do {
            numBytesRead = file.read(buffer, 0, BUFFER_SIZE);
            if(numBytesRead == BUFFER_SIZE) {
                outFile.write(cipher.doFinal(buffer, 0, numBytesRead));
            } else {
                int smallBufferSize = numBytesRead + (16 - (numBytesRead % 16));
                byte[] smallBuffer = new byte[smallBufferSize];
                System.arraycopy(buffer, 0, smallBuffer, 0, smallBufferSize);
                outFile.write(cipher.doFinal(smallBuffer, 0, smallBufferSize), 0, numBytesRead);
            }
        } while (numBytesRead == BUFFER_SIZE);
        file.close();
        outFile.close();
    }
    
    private static String rsaDecrypt(String messageOutputFile) throws Exception {
        BufferedInputStream file = new BufferedInputStream(new FileInputStream("message.ds-msg"));
        BufferedOutputStream mOut = new BufferedOutputStream(new FileOutputStream(messageOutputFile));
        BufferedOutputStream ddOut = new BufferedOutputStream(new FileOutputStream("message.dd"));

        byte[] ds = new byte[128];
        file.read(ds, 0, ds.length);

        System.out.println("Encrypted Digital Digest (RSA-En Kx– (SHA256(M))):");
        printHash(ds);

        byte[] m = new byte[BUFFER_SIZE];
        int numBytesRead;
        do {
            numBytesRead = file.read(m, 0, m.length);
            if(numBytesRead == -1) break;
            mOut.write(m, 0, numBytesRead);
        } while (numBytesRead == BUFFER_SIZE);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, xPublicK);

        byte[] dd = cipher.doFinal(ds);
        System.out.println("Decrypted Digital Digest (SHA256(M)):");
        printHash(dd);
        ddOut.write(dd);

        file.close();
        mOut.close();
        ddOut.close();

        return new String(dd, StandardCharsets.UTF_8);
    }

        // Calculate hash value
        public static String getSHA(String msgFileName) throws FileNotFoundException, NoSuchAlgorithmException,
        IOException {
            BufferedInputStream file = new BufferedInputStream(new FileInputStream(msgFileName));
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            DigestInputStream in = new DigestInputStream(file, md);
            
            //Read message 1024 bytes at a time
            int i;
            byte[] buffer = new byte[BUFFER_SIZE];
            do {
                i = in.read(buffer, 0, BUFFER_SIZE);
            } while (i == BUFFER_SIZE);
            md = in.getMessageDigest();
            in.close();
            file.close();

            byte[] hash = md.digest();

            System.out.println("Calculated Digital Digest (SHA256(M)):");
            printHash(hash);

            return new String(hash);
        }

    private static void printHash(byte[] hash){
        for (int k = 0; k<hash.length; k++) {
            String out = String.format("%2X", hash[k]).replace(' ', '0');
            System.out.print(out + " ") ;
            if ((k + 1) % 16 == 0) System.out.println("");
        }
        System.out.println("");
    }

    //read public key parameters from a file and generate the public key
    private static PublicKey readPubKeyFromFile(String keyFileName)
            throws IOException {
        ObjectInputStream oin = new ObjectInputStream(new FileInputStream(keyFileName));
        try {
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
        } finally {
            oin.close();
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
}
