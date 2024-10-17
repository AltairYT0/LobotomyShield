package ls.key;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

public class KeyCryptography {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int IV_SIZE = 16;
    private static final int SALT_SIZE = 16;
    private static final int ITERATIONS = 65536;
    private static final int KEY_LENGTH = 256;

    public static String encrypt(String plaintext, String key) throws Exception {
        if (plaintext == null || key == null) {
            throw new IllegalArgumentException("Text and key must not be null.");
        }
        if (plaintext.isEmpty() || key.isEmpty()) {
            throw new IllegalArgumentException("Text and key must not be empty.");
        }

        byte[] initializationVector = new byte[IV_SIZE];
        SecureRandom randomGenerator = new SecureRandom();
        randomGenerator.nextBytes(initializationVector);
        IvParameterSpec ivParams = new IvParameterSpec(initializationVector);

        byte[] saltBytes = new byte[SALT_SIZE];
        randomGenerator.nextBytes(saltBytes);

        SecretKey secretKey = deriveKey(key, saltBytes);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);

        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        byte[] combinedBytes = new byte[SALT_SIZE + IV_SIZE + encryptedBytes.length];
        System.arraycopy(saltBytes, 0, combinedBytes, 0, SALT_SIZE);
        System.arraycopy(initializationVector, 0, combinedBytes, SALT_SIZE, IV_SIZE);
        System.arraycopy(encryptedBytes, 0, combinedBytes, SALT_SIZE + IV_SIZE, encryptedBytes.length);

        return Base64.getEncoder().encodeToString(combinedBytes);
    }

    public static String decrypt(String encryptedText, String key) throws Exception {
        if (encryptedText == null || key == null) {
            throw new IllegalArgumentException("Encrypted text and key must not be null.");
        }
        if (encryptedText.isEmpty() || key.isEmpty()) {
            throw new IllegalArgumentException("Encrypted text and key must not be empty.");
        }

        byte[] combinedBytes = Base64.getDecoder().decode(encryptedText);

        if (combinedBytes.length < SALT_SIZE + IV_SIZE) {
            throw new IllegalArgumentException("Invalid encrypted text.");
        }

        byte[] saltBytes = new byte[SALT_SIZE];
        byte[] initializationVector = new byte[IV_SIZE];
        byte[] encryptedBytes = new byte[combinedBytes.length - SALT_SIZE - IV_SIZE];

        System.arraycopy(combinedBytes, 0, saltBytes, 0, SALT_SIZE);
        System.arraycopy(combinedBytes, SALT_SIZE, initializationVector, 0, IV_SIZE);
        System.arraycopy(combinedBytes, SALT_SIZE + IV_SIZE, encryptedBytes, 0, encryptedBytes.length);

        SecretKey secretKey = deriveKey(key, saltBytes);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(initializationVector));

        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    private static SecretKey deriveKey(String key, byte[] salt) throws Exception {
        KeySpec spec = new PBEKeySpec(key.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] derivedKey = factory.generateSecret(spec).getEncoded();

        return new SecretKeySpec(derivedKey, ALGORITHM);
    }
}
