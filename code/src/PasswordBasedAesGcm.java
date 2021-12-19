import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import javax.crypto.spec.*;
import javax.crypto.*;

import java.util.Arrays;
import java.util.Base64;

/**
 * class PasswordBasedAesGcm
 * Implements safe symmetric encryption using AES algorithm and GCM block cipher mode of operation.
 * The key is derived from a password that must be passed to the encryption / decryption method.
 * All modifiable values are checked whether they are both, supported and safe.
 * <p>
 * Important:
 * This code is for educational purpose only.
 * Error handling is not appropriate!
 */
public class PasswordBasedAesGcm {
    final static int[] validKeySizes = {128, 192, 256};
    final static int[] validTagLengths = {96, 104, 112, 120, 128};

    private int keyLength;                  // keyLength in bits, keyLength in {128, 192, 256}
    private int saltLength;                 // saltLength in Bytes, saltLength > 8
    private int ivLength;                   // ivLength in Bytes, ivLength > 1
    private int tagLength;                  // tagLength in bits, tagLength in {96, 104, 112, 120, 128}
    private final int ITERATIONS = 1000;    // iterations for key derivation function, ITERATIONS > 1000


    /**
     * Constructor
     * @param keyLength
     * @param saltLength
     * @param ivLength
     * @param tagLength
     */
    private PasswordBasedAesGcm(int keyLength, int saltLength, int ivLength, int tagLength) {
        assert (Arrays.binarySearch(validKeySizes, keyLength) > 0);
        assert (Arrays.binarySearch(validTagLengths, tagLength) > 0);
        assert (saltLength > 7);
        assert (ivLength > 0);

        this.keyLength = keyLength;
        this.saltLength = saltLength;
        this.ivLength = ivLength;
        this.tagLength = tagLength;

        assert (this.isValid());
    }

    /**
     * instantiates a default PasswordBased encryption object:
     * keyLength: 128
     * saltLength: 8
     * ivLength: 12
     * tagLength: 128
     * @return a default PasswordBasedAesGcm object
     */
    public static PasswordBasedAesGcm getInstance() {
        return new PasswordBasedAesGcm(128, 8, 12, 128);
    }


    /**
     * encrypts a given plain text using the given password for key derivation
     * @param plainText the secret message
     * @param password the password from which the key is derived
     * @return salt|iv|cipherText, concatenated as byte[] and base64 encoded
     */
    public String encrypt(String plainText, String password) throws Exception {
        try {

            // convert plaintext to byte[] (character decoding)
            byte[] plain = plainText.getBytes(StandardCharsets.UTF_8);

            SecureRandom generator = new SecureRandom();

            // derive key from password
            byte[] salt = new byte[this.saltLength];
            generator.nextBytes(salt);  // salt must be random
            SecretKey key = deriveKey(password, salt);

            // generate random initialization vector
            byte[] iv = new byte[this.ivLength];
            generator.nextBytes(iv); // iv must be random

            // prepare algorithm parameter
            GCMParameterSpec params = new GCMParameterSpec(this.tagLength, iv);

            // instantiate and initialize cipher object
            Cipher encryptor = Cipher.getInstance("AES/GCM/NOPADDING");
            encryptor.init(Cipher.ENCRYPT_MODE, key, params);

            // encrypt data
            byte[] cipher = encryptor.doFinal(plain);


            // concatenate salt, iv and cipher text
            byte[] result = concatenateSaltIvAndCipherText(salt, iv, cipher);

            // convert to string (character encoding)
            return Base64.getEncoder().encodeToString(result);


        } catch (Exception e) {
            /* Error Handling is not appropriate! */
            throw new Exception("Failed at Encryption! \n" + e.getClass() + "\n" + e.getMessage());
        }

    }

    /**
     * encrypts the file located at inputPath and stores it in outputPath
     * @param inputPath the relative path to the file that should be encrypted
     * @param outputPath the relative path to the file in which the encryption result should be stored
     * @param password the password from which the key is deriven
     * @return salt|iv, concatenated as byte[] and base64 encoded
     * @throws Exception
     */
    public String encryptFile(String inputPath, String outputPath, String password) throws Exception {
        try {
            // prepare encryption parameters
            SecureRandom generator = new SecureRandom();

            // derive key from password
            byte[] salt = new byte[this.saltLength];
            generator.nextBytes(salt);  // salt must be random
            SecretKey key = this.deriveKey(password, salt);

            // generate random initialization vector
            byte[] iv = new byte[this.ivLength];
            generator.nextBytes(iv); // iv must be random

            // prepare algorithm parameter
            GCMParameterSpec params = new GCMParameterSpec(this.tagLength, iv);

            // instantiate and initialize cipher object
            Cipher encryptor = Cipher.getInstance("AES/GCM/NOPADDING");
            encryptor.init(Cipher.ENCRYPT_MODE, key, params);

            // initialize streams
            FileInputStream in = new FileInputStream(new File(inputPath));
            FileOutputStream out = new FileOutputStream(new File(outputPath));
            CipherInputStream c = new CipherInputStream(in, encryptor);

            // read and encrypt block wise
            byte[] b = new byte[256]; // Buffer - one block is 256 Byte
            int i = c.read(b); // read and encrypt the first block
            while (i != -1) {
                out.write(b, 0, i); // write the result to the output file
                i = c.read(b); // read and encrypt the next block
            }

            // close streams
            c.close();
            in.close();
            out.close();

            // return salt and iv, concatenated as byte[] and base64 encoded
            byte[] result = concatenateSaltAndIv(salt, iv);
            return Base64.getEncoder().encodeToString(result);


        } catch (Exception e) {
            throw new Exception("Failed at Encryption: " + e.getClass() + "\n" + e.getMessage());
        }
    }

    /**
     * decrypts the given cipher text deriving the key from the given password
     * salt and initialization vector must be prepended to the cipher text
     *
     * @param saltIvAndCipherText salt and initialization that were used for encryption prepended to the encryption result and base64 encoded
     * @param password           the password from which the key is derived
     * @return the plain text
     * @throws Exception
     */
    public String decrypt(String saltIvAndCipherText, String password) throws Exception {
        try {

            // convert saltIVAndCipherText to byte[] (character decoding)
            byte[] data = Base64.getDecoder().decode(saltIvAndCipherText);

            // separate salt, iv, and cipher text
            byte[] salt = Arrays.copyOfRange(data, 0, this.saltLength);
            byte[] iv = Arrays.copyOfRange(data, this.saltLength, (this.saltLength + this.ivLength));
            byte[] cipherText = Arrays.copyOfRange(data, (this.saltLength + this.ivLength), data.length);

            // restore the parameters
            SecretKey key = deriveKey(password, salt);
            GCMParameterSpec params = new GCMParameterSpec(this.tagLength, iv);

            // decrypt the data
            Cipher decryptor = Cipher.getInstance("AES/GCM/NOPADDING");
            decryptor.init(Cipher.DECRYPT_MODE, key, params);
            byte[] plain = decryptor.doFinal(cipherText);

            // convert plain text to string
            return new String(plain, StandardCharsets.UTF_8);


        } catch (Exception e) {
            /* Error Handling is not appropriate! */
            throw new Exception("Decryption failed! \n" + e.getClass() + "\n" + e.getMessage());
        }
    }


    /**
     * decrypts the file located at the inputPath and stores it in outputPath
     * @param inputPath, the relative path to the encrypted file
     * @param outputPath, the relative path to the file where the decryption result should be stored
     * @param saltAndIv, the salt and the initialization vector that were used for encryption, concatenated as byte[] and base64 encoded
     * @param password, the password from which the key should be derived
     * @throws Exception
     */
    public void decryptFile(String inputPath, String outputPath, String saltAndIv, String password) throws Exception {
        try {
            // restore parameters
            byte[] parameters = Base64.getDecoder().decode(saltAndIv);
            byte[] salt = Arrays.copyOfRange(parameters, 0, this.saltLength);
            byte[] iv = Arrays.copyOfRange(parameters, this.saltLength, parameters.length);

            SecretKey key = this.deriveKey(password, salt);
            GCMParameterSpec params = new GCMParameterSpec(this.tagLength, iv);

            // initialize cipher object
            Cipher decryptor = Cipher.getInstance("AES/GCM/NOPADDING");
            decryptor.init(Cipher.DECRYPT_MODE, key, params);

            // initialize the streams
            FileInputStream in = new FileInputStream(new File(inputPath));
            FileOutputStream out = new FileOutputStream(new File(outputPath));
            CipherInputStream c = new CipherInputStream(in, decryptor);

            // read and decrypt block wise
            byte[] b = new byte[8]; // Buffer - one block is 8 Byte
            int i = c.read(b); // read and decrypt the first block
            while (i != -1) {
                out.write(b, 0, i); // write the result to the output file
                i = c.read(b); // read and decrypt the next block
            }

        } catch (Exception e) {
            /* Error Handling is not appropriate! */
            throw new Exception("Decryption failed! \n" + e.getClass() + "\n" + e.getMessage());

        }
    }


    /**
     * method for customizing the keyLength
     *
     * @param length, must be in {128, 196, 256}
     * @throws InvalidCryptoParameterException if the given length is not supported by AES
     */
    public void setKeyLength(int length) throws InvalidCryptoParameterException {
        if (Arrays.binarySearch(validKeySizes, keyLength) < 0)
            throw new InvalidCryptoParameterException("Unsupported keySize: must be in {128, 192, 256}");
        this.keyLength = length;
        assert (this.isValid());
    }

    /**
     * method for customizing saltLength
     *
     * @param length must be >= 8
     * @throws UnsafeCryptoParameterException if the given length is not safe (< 8)
     */
    public void setSaltLength(int length) throws UnsafeCryptoParameterException {
        if (saltLength < 8)
            throw new UnsafeCryptoParameterException("saltLength must be > 7");
        this.saltLength = length;
        assert (this.isValid());
    }

    /**
     * method for customizing ivLength
     *
     * @param length must be positive
     * @throws InvalidCryptoParameterException if length < 1
     */
    public void setIvLength(int length) throws InvalidCryptoParameterException {
        if (length < 1) {
            throw new InvalidCryptoParameterException("ivLength must be > 0");
        }
        this.ivLength = length;
        assert (this.isValid());
    }

    /**
     * method for customizing tagLength
     *
     * @param length must be in {96, 104, 112, 120, 128}
     * @throws InvalidCryptoParameterException if the given length is not supported by GCM
     */
    public void setTagLength(int length) throws InvalidCryptoParameterException {
        if (Arrays.binarySearch(validTagLengths, length) < 0) {
            throw new InvalidCryptoParameterException("Unsupported tagLength: must be in {96, 104, 112, 120, 128}");
        }
        this.tagLength = length;
        assert (this.isValid());
    }

    public int getKeyLength() {
        return this.keyLength;
    }

    public int getSaltLength() {
        return this.saltLength;
    }

    public int getIvLength() {
        return this.ivLength;
    }

    public int getTagLength() {
        return this.tagLength;
    }

    public int getIterations() {
        return this.ITERATIONS;
    }


    /**
     * derives a key from a given password using the specified salt
     * @param password should be a safe
     * @param salt should be generated randomly for each encryption
     * @return a SecretKey for AES encryption
     * @throws Exception
     */
    private SecretKey deriveKey(String password, byte[] salt) throws Exception {
        try {
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, this.ITERATIONS, this.keyLength);
            SecretKey key = keyFactory.generateSecret(keySpec); // the secret key
            byte[] keyMaterial = key.getEncoded();
            keySpec.clearPassword();
            return new SecretKeySpec(keyMaterial, "AES");
        } catch (Exception e) {
            /* Error Handling is not appropriate! */
            throw new Exception("Key Derivaton failed! \n" + e.getClass() + "\n" + e.getMessage());
        }

    }

    /**
     * prepends the salt and the initialization vector used for encryption to the encryption result
     *
     * @param salt, the salt used for key derivation
     * @param iv, the initialization vector used for encryption
     * @param cipherText, the encryption result, consisting of the cipher text and the authentication tag
     * @return salt|iv|cipherText concatenated as byte[]
     */
    private byte[] concatenateSaltIvAndCipherText(byte[] salt, byte[] iv, byte[] cipherText) {
        byte[] result = new byte[this.saltLength + this.ivLength + cipherText.length];
        for (int i = 0; i < result.length; i++) {
            if (i < this.saltLength) {
                // fill in salt
                result[i] = salt[i];
            } else if (i < (this.saltLength + this.ivLength)) {
                // fill in IV
                result[i] = iv[i - this.saltLength];
            } else { // saltLength + ivLength <= i
                // fill in cipher text
                result[i] = cipherText[i - (this.saltLength + this.ivLength)];
            }
        }
        return result;
    }

    /**
     * concatenates the salt and the initialization vector that were used for the encryption of a file
     * @param salt, the salt used for key derivation
     * @param iv, the iv used during encryption
     * @return salt|iv
     */
    private byte[] concatenateSaltAndIv(byte[] salt, byte[] iv) {
        byte[] result = new byte[this.saltLength + this.ivLength];
        for (int i = 0; i < result.length; i++) {
            if (i < saltLength) {
                result[i] = salt[i];
            } else {
                result[i] = iv[i - saltLength];
            }
        }
        return result;
    }

    /**
     * Class Invariant
     * @return whether the object is in a valid state
     */
    private boolean isValid() {
        return Arrays.binarySearch(validKeySizes, this.keyLength) > 0 &&
                Arrays.binarySearch(validTagLengths, this.tagLength) > 0 &&
                this.ivLength > 1 &&
                this.saltLength > 7 &&
                this.ITERATIONS >= 1000;
    }

}


class UnsafeCryptoParameterException extends Exception {
    public UnsafeCryptoParameterException(String message) {
        super(message);
    }
}

class InvalidCryptoParameterException extends Exception {
    public InvalidCryptoParameterException(String message) {
        super(message);
    }
}
