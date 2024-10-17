package ls.lobotomy;

import ls.key.KeyCryptography;
import ls.utils.KeyGen;

import java.util.Base64;

public class LobotomyEncryption {

    private final String encryptionKey;
    private final String encryptionMode;

    public LobotomyEncryption(String encryptionMode) {
        this.encryptionKey = KeyGen.generateRandomKey();
        this.encryptionMode = encryptionMode;
    }

    public String encrypt(String plaintext) {
        if (plaintext == null || plaintext.trim().isEmpty()) {
            throw new IllegalArgumentException("Input cannot be null or empty");
        }
        try {
            byte[] byteData = KeyCryptography.encrypt(plaintext, encryptionKey).getBytes();

            switch (encryptionMode) {
                case "lobotomy/cas/ascii":
                    return transformToASCII(byteData);
                case "lobotomy/cas/unicode":
                    return transformToUnicode(byteData);
                case "lobotomy/cas/xor":
                    return applyXorEncryption(byteData);
                case "lobotomy/cas/base":
                    return encodeToBase64(byteData);
                default:
                    throw new IllegalArgumentException("Invalid mode: " + encryptionMode);
            }
        } catch (Exception e) {
            throw new RuntimeException("Error during encryption", e);
        }
    }

    private String encodeToBase64(byte[] byteData) {
        return Base64.getEncoder().encodeToString(byteData);
    }

    private String transformToASCII(byte[] byteData) {
        StringBuilder encrypted = new StringBuilder();
        for (byte b : byteData) {
            char asciiChar = (char) ((b + 100) % 128);
            encrypted.append(asciiChar);
        }
        return encrypted.toString();
    }

    private String transformToUnicode(byte[] byteData) {
        StringBuilder encrypted = new StringBuilder();
        for (byte b : byteData) {
            encrypted.append((char) (b + 1000));
        }
        return encrypted.toString();
    }

    private String applyXorEncryption(byte[] byteData) {
        byte[] result = new byte[byteData.length];
        for (int i = 0; i < byteData.length; i++) {
            result[i] = (byte) (byteData[i] ^ 42);
        }
        return new String(result);
    }

    public String getKey() {
        return this.encryptionKey;
    }

    public String getMode() {
        return encryptionMode;
    }
}
