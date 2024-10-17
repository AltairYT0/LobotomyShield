package ls.lobotomy;

import ls.key.KeyCryptography;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class LobotomyDecryption {

    private final String decryptionKey;
    private final String decryptionMode;

    public LobotomyDecryption(String decryptionMode, String decryptionKey) {
        if (decryptionKey == null || decryptionKey.trim().isEmpty()) {
            throw new IllegalArgumentException("Key cannot be null or empty");
        }
        this.decryptionKey = decryptionKey;
        this.decryptionMode = decryptionMode;
    }

    public String decrypt(String ciphertext) {
        if (ciphertext == null || ciphertext.trim().isEmpty()) {
            throw new IllegalArgumentException("Encrypted input cannot be null or empty");
        }
        byte[] byteData;
        try {
            switch (decryptionMode) {
                case "lobotomy/cas/ascii":
                    byteData = transformFromASCII(ciphertext);
                    break;
                case "lobotomy/cas/unicode":
                    byteData = transformFromUnicode(ciphertext);
                    break;
                case "lobotomy/cas/xor":
                    byteData = applyXorDecryption(ciphertext);
                    break;
                case "lobotomy/cas/base":
                    byteData = decodeFromBase64(ciphertext);
                    break;
                default:
                    throw new IllegalArgumentException("Invalid mode: " + decryptionMode);
            }
            byte[] decryptedBytes = KeyCryptography.decrypt(new String(byteData), decryptionKey).getBytes();

            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Error during decryption", e);
        }
    }

    private byte[] decodeFromBase64(String base64Input) {
        return Base64.getDecoder().decode(base64Input);
    }

    private byte[] applyXorDecryption(String input) {
        byte[] result = new byte[input.getBytes().length];
        for (int i = 0; i < input.getBytes().length; i++) {
            result[i] = (byte) (input.getBytes()[i] ^ 42);
        }
        return result;
    }

    private byte[] transformFromASCII(String asciiInput) {
        byte[] decrypted = new byte[asciiInput.length()];
        for (int i = 0; i < asciiInput.length(); i++) {
            decrypted[i] = (byte) ((asciiInput.charAt(i) - 100 + 128) % 128);
        }
        return decrypted;
    }

    private byte[] transformFromUnicode(String unicodeInput) {
        byte[] decrypted = new byte[unicodeInput.length()];
        for (int i = 0; i < unicodeInput.length(); i++) {
            decrypted[i] = (byte) (unicodeInput.charAt(i) - 1000);
        }
        return decrypted;
    }

    public String getKey() {
        return this.decryptionKey;
    }

    public String getMode() {
        return decryptionMode;
    }
}
