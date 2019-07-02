package EncryptionToolkit.AES;

import EncryptionToolkit.Utils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

/**
 * AES
 * @author Marco
 */
public class AES {

    /** Bit-length of the key to use in AES */
    private int KEY_BIT_LEN;

    /** PRNG for key generation */
    private final SecureRandom srand = new SecureRandom();

    /** Key Generation Iteration count */
    private int KEY_GEN_ITER = 9487;

    /** Symmetric Key for en-/decryption */
    private String key;

    /** Initialization vector for AES calculation */
    private String iv;

    /** Character Encoding for plain-text */
    private Charset ENCODING = StandardCharsets.UTF_8;

    /**
     * Define the transformation of current crypto-algorithm, may include the name of the
     * algorithm (e.g. AES), a feedback mode (e.g. CBC), and a padding scheme
     * (e.g. ISO10126Padding), each separated by a front slash '/'
     *
     * [NOTE] For a complete list of valid names for crypto-algorithm transformation, see
     * https://docs.oracle.com/javase/9/security/oracleproviders.htm#JSSEC-GUID-A47B1249-593C-4C38-A0D0-68FA7681E0A7
     */
    private String CONFIG = "AES/CBC/PKCS5Padding";

    private AES(int keyBitLen) {
        this.KEY_BIT_LEN = keyBitLen;
    }

    private AES(String key, String iv) {
        this.key = new String(Utils.clampKeySize(key.getBytes()), ENCODING);
        this.iv = new String(Utils.clampKeySize(iv.getBytes()), ENCODING);
    }

    public static AES initWithKeySize(int keyBitLen) {
        return new AES(keyBitLen);
    }

    public static AES initWithAESParams(String key, String iv) {
        return new AES(key, iv);
    }

    /**
     * Manually configure iteration round for password-based key generation
     * @param iterRound
     * @return
     */
    public void setKeyGenerationIteration(int iterRound) {
        this.KEY_GEN_ITER = iterRound;
    }

    /**
     * Perform AES encryption
     * @param plainText: Plain text to be encrypted
     * @param keyMaterial: Password sequence for key generation
     * @return The cipher text, the generated key, along with the randomly-generated
     *      initialization vector (IV), all encoded in Base64 format
     */
    public String[] encrypt(String plainText, char[] keyMaterial) {
        try {
            // Configure SecretKeyFactory for key generation
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] salt = Utils.getNextRandomBigIntegerOfLength(srand, "", KEY_BIT_LEN).toByteArray();

            // Generate a symmetric private key for AES
            KeySpec keySpec = new PBEKeySpec(keyMaterial, salt, KEY_GEN_ITER, KEY_BIT_LEN);
            SecretKey secretKey = factory.generateSecret(keySpec);

            // Perform encryption
            return encrypt(plainText, new String(secretKey.getEncoded(), ENCODING), null);

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Perform AES encryption with pre-defined AES parameters
     * @param plainText: Plain text to be encrypted
     * @return The cipher text encoded in Base64 format
     */
    public String encrypt(String plainText) {
        return encrypt(plainText, this.key, this.iv)[0];
    }

    /**
     * Perform AES encryption with supplied symmetric key and initialization vector
     * @param plainText: Plain text to be encrypted
     * @param key: Symmetric key for AES calculation (Non-nullable)
     * @param iv: Initialization Vector for AES calculation (Nullable)
     * @return The cipher text, the generated key, along with the randomly-generated
     *      initialization vector (IV), all encoded in base-64 format
     */
    public String[] encrypt(String plainText, String key, String iv) {
        try {
            // Parse plain text as UTF-8 bytes
            byte[] plainBytes = plainText.getBytes(this.ENCODING);

            // Parse key into byte array
            byte[] keyBytes = Utils.clampKeySize(key.getBytes(this.ENCODING));

            // Parse key into byte array
            byte[] ivBytes = iv == null ? null : Utils.clampKeySize(iv.getBytes(this.ENCODING));

            // Generate a symmetric private key for AES
            SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

            // Initialize AES algorithm, operate in CBC mode with ISO10126Padding by default
            Cipher cipher = Cipher.getInstance(CONFIG);

            // Generate a initialization vector (IV) for Cipher-block chaining (CBC) operation if necessary
            if (ivBytes == null) {
                ivBytes = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
            }
            IvParameterSpec ivParam = new IvParameterSpec(ivBytes);

            // Perform encryption
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParam);
            byte[] cipherBytes = cipher.doFinal(plainBytes);

            // Encode the cipher bytes into Base-64 string
            String cipherText = Base64.getEncoder().encodeToString(cipherBytes);
            String keyText = Base64.getEncoder().encodeToString(keyBytes);
            String ivText = Base64.getEncoder().encodeToString(ivBytes);

            return new String[]{cipherText, keyText, ivText};

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException |
                InvalidKeyException | InvalidAlgorithmParameterException | InvalidParameterSpecException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Perform AES decryption based on the cipher text and the same set of
     * parameters used in the encryption process
     * @param cipherText: Cipher text to be decrypted
     * @param key: Should be the same key sequence used in encryption
     * @param iv: Should be the same initialization vector used in encryption
     * @return
     */
    public String decrypt(String cipherText, String key, String iv) {
        try {
            // Parse cipher text to byte array
            byte[] cipherBytes = Base64.getDecoder().decode(cipherText);

            // Parse key into byte array
            byte[] keyBytes = Utils.clampKeySize(key.getBytes(this.ENCODING));

            // Parse key into byte array
            byte[] ivBytes = iv == null ? null : Utils.clampKeySize(iv.getBytes(this.ENCODING));

            // Generate a initialization vector (IV) for Cipher-block chaining (CBC) operation
            IvParameterSpec ivParam = new IvParameterSpec(ivBytes);

            SecretKeySpec secret = new SecretKeySpec(keyBytes, "AES");

            // Initialize AES algorithm, operate in CBC mode with PKCS5Padding by default
            Cipher cipher = Cipher.getInstance(CONFIG);
            cipher.init(Cipher.DECRYPT_MODE, secret, ivParam);

            // Perform encryption
            byte[] plainBytes = cipher.doFinal(cipherBytes);

            return new String(plainBytes, ENCODING);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException |
                InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Perform AES decryption based on the cipher text and the same set of
     * parameters used in the encryption process
     * @param cipherText: Cipher text to be decrypted
     * @return
     */
    public String decrypt(String cipherText) {
        return decrypt(cipherText, this.key, this.iv);
    }

    /**
     * Check if supplied key length (in byte) is valid for AES(128/192/256)
     * @param byteLen
     * @return
     */
    public boolean isKeyByteLenValid(int byteLen) {
        return byteLen == 16;
    }

    /**
     * Simulate a complete round of encryption and decryption
     * @param printLog
     * @return Time consumed for en-/decryption
     */
    public long doEncryptDecrypt(boolean printLog) {
        // Record start time for obtaining performance benchmark
        long startTime = System.currentTimeMillis();

        String plainText = "abcdefghijklmnopqrstuvwxyz";
        char[] keyMaterial = "pwd".toCharArray();
        String[] encryptInfo = encrypt(plainText, keyMaterial);

        // Record time lapse up to encryption is completed
        long encryptEndTime = System.currentTimeMillis();

        String cipherText = encryptInfo[0];
        String key = encryptInfo[1];
        String iv = encryptInfo[2];
        String recoveredPlainedText = decrypt(cipherText, key, iv);

        // Record time lapse up to encryption is completed
        long decryptEndTime = System.currentTimeMillis();

        if (printLog) {
            System.out.println("PLAIN TEXT: " + plainText);
            System.out.println("CIPHER TEXT: " + cipherText);
            System.out.println("SYMMETRIC KEY: " + key);
            System.out.println("INITIALIZATION VECTOR: " + iv);
            System.out.println("RECOVERED PLAIN TEXT: " + recoveredPlainedText);

            // Performance benchmark
            System.out.println("ENCRYPT TIME LAPSED: " + (encryptEndTime - startTime) + " ms");
            System.out.println("DECRYPT TIME LAPSED: " + (decryptEndTime - encryptEndTime) + " ms");
            System.out.println("TOTAL TIME LAPSED: " + (decryptEndTime - startTime) + " ms");
        }

        return decryptEndTime - startTime;
    }

    public static void main(String[] args) {
        AES aes = AES.initWithKeySize(128);
        aes.setKeyGenerationIteration(9487);
        aes.doEncryptDecrypt(true);
    }
}
