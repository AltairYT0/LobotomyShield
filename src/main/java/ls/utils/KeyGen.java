package ls.utils;

import java.security.SecureRandom;
import java.util.Base64;
public class KeyGen {

    public static String generateRandomKey() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] key = new byte[256 / 8];
        secureRandom.nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }
}
