public class Main {

    public static void main(String[] args) {
        String password = "apsd23*?skAa";
        String plainText = "This is my secret message";

        System.out.println("Example No. 1: Using the default PasswordBasedEncryption object");
        example1(password, plainText);
        System.out.println("\nExample No. 2: Using a customized PasswordBasedEncryption object");
        example2(password, plainText);
        System.out.println("\nExample No. 3: File Encryption");
        example3(password);
        System.out.println("\nExample No. 4: Using a customized PasswordBasedEncryption with invalid / unsafe parameter (tagLength = 32)");
        example4(password, plainText);


    }

    private static void example1(String password, String plainText) {
        try {

            PasswordBasedAesGcm crypto = PasswordBasedAesGcm.getInstance();
            String cipherText = crypto.encrypt(plainText, password);
            String decrypted = crypto.decrypt(cipherText, password);


            System.out.println("Original Message: " + plainText);
            System.out.println("Encrypted Message: " + cipherText);
            System.out.println("Decrypted Message: " + decrypted);


        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static void example2(String password, String plainText) {
        try {
            PasswordBasedAesGcm crypto = PasswordBasedAesGcm.getInstance();
            crypto.setKeyLength(256);
            crypto.setIvLength(16);
            crypto.setTagLength(96);
            crypto.setSaltLength(16);

            String cipherText = crypto.encrypt(plainText, password);
            String decrypted = crypto.decrypt(cipherText, password);


            System.out.println("Encrypted Message: " + cipherText);
            System.out.println("Original Message: " + plainText);
            System.out.println("Decrypted Message: " + decrypted);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static void example3(String password) {
        PasswordBasedAesGcm crypto = PasswordBasedAesGcm.getInstance();
        String input = "./testData/plainFile.txt";
        String output_1 = "./testData/encrypted.txt";
        String output_2 = "./testData/decrypted.txt";
        System.out.println("Done.");
        try {
            String saltAndIv = crypto.encryptFile(input, output_1, password);
            crypto.decryptFile(output_1, output_2, saltAndIv, password);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

    }

    private static void example4(String password, String plainText) {
        try {
            PasswordBasedAesGcm crypto = PasswordBasedAesGcm.getInstance();
            crypto.setIvLength(16);
            crypto.setTagLength(32);
            crypto.setSaltLength(16);
            System.out.println("Original Message: " + plainText);
            String cipherText = crypto.encrypt(plainText, password);
            System.out.println("Encrypted Message: " + cipherText);
            String decrypted = crypto.decrypt(cipherText, password);
            System.out.println("Decrypted Message: " + decrypted);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}