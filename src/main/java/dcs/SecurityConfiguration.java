package dcs;

import org.apache.commons.codec.binary.Hex;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

// global security configuration
public class SecurityConfiguration {
    // the number of iterations to use for the hashing of passwords
    public static final int ITERATIONS = 1000;
    // the size of the key to generate
    public static final int KEY_SIZE = 256;

    // hash a password using PBKDF2
    public static String pbkdf2(String password, String salt, int iterations, int keySize) {
        // convert the username and password to char and byte arrays
        char[] pwd = password.toCharArray();
        byte[] slt = salt.getBytes();

        try {
            // initialise the crypto classes with the desired configuration
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            PBEKeySpec spec = new PBEKeySpec(pwd, slt, iterations, keySize);

            // hash the password using the configuration
            SecretKey key = skf.generateSecret(spec);
            byte[] res = key.getEncoded();

            // return the hashed password as a hexadecimal string
            return Hex.encodeHexString(res);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }
}
