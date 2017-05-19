import java.io.*;
import java.util.*;
import javax.crypto.*;
import java.security.*;

public class EncryptionUtil{
    /**
     * String to hold name of the encryption algorithm.
     */
    public static final String ENCRYPT_ALGORITHM = "RSA";

    /**
     * String to hold name of the signature algorithm.
     */
    public static final String SIGNATURE_ALGORITHM = "MD5withRSA";

    /**
     * Integer to hold the length of RSA key
     */
    public static final Integer RSA_KEY_LENGTH = 2048;

    /**
     * Generate key which contains a pair of private and public key using 1024
     * bytes. Store the set of keys in Prvate.key and Public.key files.
     *
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws FileNotFoundException
     */
    public static KeyPair generate(){
        KeyPair keys = null;
        try {
            final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ENCRYPT_ALGORITHM);
            keyGen.initialize(RSA_KEY_LENGTH);
            keys = keyGen.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return keys;
    }

    /**
     * Encrypt the plain text using public key.
     *
     * @param text
     *          : original plain text
     * @param key
     *          :The public key
     * @return Encrypted text
     * @throws java.lang.Exception
     */
    public static byte[] encrypt(String text, PublicKey key) {
        byte[] cipherText = null;
        try {
            // get an RSA cipher object and print the provider
            final Cipher cipher = Cipher.getInstance(ENCRYPT_ALGORITHM);
            // encrypt the plain text using the public key
            cipher.init(Cipher.ENCRYPT_MODE, key);
            cipherText = cipher.doFinal(text.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return cipherText;
    }

    /**
     * Decrypt text using private key.
     *
     * @param text
     *          :encrypted text
     * @param key
     *          :The private key
     * @return plain text
     * @throws java.lang.Exception
     */
    public static String decrypt(byte[] text, PrivateKey key) {
        byte[] dectyptedText = null;
        try {
            // get an RSA cipher object and print the provider
            final Cipher cipher = Cipher.getInstance(ENCRYPT_ALGORITHM);

            // decrypt the text using the private key
            cipher.init(Cipher.DECRYPT_MODE, key);
            dectyptedText = cipher.doFinal(text);

        } catch (Exception e) {
            e.printStackTrace();
        }

        return new String(dectyptedText);
    }

    /**
     * Sign the text using privete key.
     *
     * @param text
     *          :origin text
     * @param key
     *          :the private key
     * @return signed text
     * @throws java.lang.Exception
     */
    public static byte[] sign(String text, PrivateKey key){
        byte[] sign = null;
        try{
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initSign(key);
            signature.update(text.getBytes());
            sign = signature.sign();
        } catch(Exception e){
            e.printStackTrace();
        }
        return sign;
    }

    /**
     * Verify if the signed text belongs to the owner of the private key.
     * @param text
     *          :origin text
     * @param key
     *          :public key
     * @param sign
     *          :signed text
     * @return boolean,if verification succeed,return true，otherwise return false
     * @throws java.lang.Exception
     **/
    public static boolean verify(String text,PublicKey key,byte[] sign) {
        Boolean result = false;
        try{
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initVerify(key);
            signature.update(text.getBytes());
            result = signature.verify(sign);
        }catch(Exception e){
            e.printStackTrace();
        }
        return result;
    }

    /**
     * Test the EncryptionUtil
     */
    public static void main(String[] args) {

        try {
            Scanner sc = new Scanner(System.in);

            KeyPair keys = generate();
            final PublicKey publicKey = keys.getPublic();
            final PrivateKey privateKey = keys.getPrivate();

            final String originalText = sc.next();

            // Encrypt the string using the public key
            final byte[] cipherText = encrypt(originalText, publicKey);
            final byte[] signText = sign(originalText, privateKey);

            // Decrypt the cipher text using the private key.
            final String plainText = decrypt(cipherText, privateKey);

            final Boolean verifyResult = verify(originalText, publicKey,signText);

            // Printing the Original, Encrypted and Decrypted Text
            System.out.println("Original: " + originalText);
            System.out.println("Encrypted: " + cipherText);
            System.out.println("Decrypted: " + plainText);
            System.out.println("Signed: " + signText);
            System.out.println("Decrypted: " + verifyResult);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
