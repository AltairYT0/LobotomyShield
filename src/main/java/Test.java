import ls.lobotomy.LobotomyDecryption;
import ls.lobotomy.LobotomyEncryption;

public class Test {

    public static void main(String[] args) {
        LobotomyEncryption encryption = new LobotomyEncryption("lobotomy/cas/xor");
        String originalText = "Hello World!";
        String encryptedText = encryption.encrypt(originalText);

        System.out.println("Encrypted: " + encryptedText);
        System.out.println("Key: " + encryption.getKey());

        LobotomyDecryption decryption = new LobotomyDecryption("lobotomy/cas/xor", encryption.getKey());
        String decryptedText = decryption.decrypt(encryptedText);

        System.out.println("Decrypted: " + decryptedText);
    }
}