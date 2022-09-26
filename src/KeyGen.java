import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;

public class KeyGen {
    private static final Scanner sysIn = new Scanner(System.in);     // Scanner object for reading user inputs

    public static void main(String[] args) {
        try {
            // Generate Keys
            KeyPair senderKeys = genRSAKeys();
            KeyPair receiverKeys = genRSAKeys();
            KeyFactory factory = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec senderPubKSpec = factory.getKeySpec(senderKeys.getPublic(),
                                                                RSAPublicKeySpec.class);
            RSAPrivateKeySpec senderPrivateKSpec = factory.getKeySpec(senderKeys.getPrivate(),
                                                                RSAPrivateKeySpec.class);
            RSAPublicKeySpec receiverPubKSpec = factory.getKeySpec(receiverKeys.getPublic(),
                                                                RSAPublicKeySpec.class);
            RSAPrivateKeySpec receiverPrivateKSpec = factory.getKeySpec(receiverKeys.getPrivate(),
                                                                RSAPrivateKeySpec.class);

            //save the parameters of the keys to the files (X is sender, y is receiver)
            saveToFile("XPublic.key", senderPubKSpec);
            saveToFile("XPrivate.key", senderPrivateKSpec);
            saveToFile("YPublic.key", receiverPubKSpec);
            saveToFile("YPrivate.key", receiverPrivateKSpec);
            genSymmetricKey();
        } catch (InvalidKeySpecException e) {
            System.out.print("Error getting RSA key specifications");
            e.printStackTrace();
        } catch (IOException e) {
            System.out.print("Error saving keys to file");
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            System.out.print("Error loading RSA algorithm instance");
            e.printStackTrace();
        }
    }

    //Generate a pair of keys use .getPublic() or .getPrivate() on returned object
    private static KeyPair genRSAKeys() throws NoSuchAlgorithmException {
        SecureRandom random = new SecureRandom();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024, random);     //1024: key size in bits
            //when key size of RSA is 1024 bits, the RSA Plaintext block
            //size needs to be <= 117 bytes; and the RSA Cypher-text
            //block is always 128 Bytes (1024 bits) long.
        return generator.generateKeyPair();
    }

    // Save the parameters of the public and private keys to file
    public static void saveToFile(String fileName, BigInteger mod,
                                  BigInteger exp) throws IOException {
        System.out.println("Writing to " + fileName + ":\n    modulus = " +
                mod.toString() + "\n    exponent = " + exp.toString() + "\n");

        ObjectOutputStream oOutStream = new ObjectOutputStream(
                new BufferedOutputStream(new FileOutputStream(fileName)));
        oOutStream.writeObject(mod);
        oOutStream.writeObject(exp);
        oOutStream.close();
    }

    // Save the parameters an RSAPublicKeySpec to file
    public static void saveToFile(String fileName, RSAPublicKeySpec pubKSpec) throws IOException {
        BigInteger mod = pubKSpec.getModulus();
        BigInteger exp = pubKSpec.getPublicExponent();
        saveToFile(fileName, mod, exp);
    }

    // Save the parameters an RSAPrivateKeySpec to file
    public static void saveToFile(String fileName, RSAPrivateKeySpec privateKSpec) throws IOException {
        BigInteger mod = privateKSpec.getModulus();
        BigInteger exp = privateKSpec.getPrivateExponent();
        saveToFile(fileName, mod, exp);
    }

    // Generate Symmetric key from user input and write it to a file
    private static void genSymmetricKey() throws IOException {
        System.out.print("Please input a 16-character string to generate the symmetric key: ");
        String key = "";

        // Get 16-character string from user to use as key
        while(key.length() != 16) {
            if(key.length() != 0) {
                System.out.print("Wrong number of characters, Please input a 16-character string: ");
            }
            key = sysIn.nextLine();  // Read user input
        }

        // Write key to file
        byte[] symKey = key.getBytes(StandardCharsets.UTF_8);
        BufferedOutputStream symKeyFile = new BufferedOutputStream(new FileOutputStream("symmetric.key"));
        symKeyFile.write(symKey, 0, symKey.length);
        symKeyFile.close();
    }
}

















