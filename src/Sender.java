import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class Sender {

    public static void main(String[] args) {
        try {
            readPubKeyFromFile("XPublic.key");
            readPrivKeyFromFile("XPrivate.key");
            readPubKeyFromFile("YPublic.key");
            readPrivKeyFromFile("YPrivate.key");
            loadSymmetricKey();
        } catch (IOException e) {
            System.out.println("Error finding/reading keys");
            e.printStackTrace();
        }
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

    //read public key parameters from a file and generate the public key
    public static PublicKey readPubKeyFromFile(String keyFileName)
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
    public static PrivateKey readPrivKeyFromFile(String keyFileName)
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
