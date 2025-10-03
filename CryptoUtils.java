package cryptoaes;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class CryptoUtils {

    // -- RSA helpers -------------------------------------------------------
    public static KeyPair generateRSAKeyPair(int bits) throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(bits, SecureRandom.getInstanceStrong());
        return kpg.generateKeyPair();
    }

    public static byte[] rsaEncrypt(byte[] data, PublicKey pub) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, pub);
        return cipher.doFinal(data);
    }

    public static byte[] rsaDecrypt(byte[] data, PrivateKey priv) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, priv);
        return cipher.doFinal(data);
    }

    // -- AES helpers -------------------------------------------------------
    public static byte[] generateAESKeyBytes(int bytesLength) {
        byte[] key = new byte[bytesLength];
        SecureRandom rng;
        try {
            rng = SecureRandom.getInstanceStrong();
        } catch (Exception e) {
            rng = new SecureRandom();
        }
        rng.nextBytes(key);
        return key;
    }

    public static SecretKeySpec makeAESKeyFromBytes(byte[] keyBytes) {
        return new SecretKeySpec(keyBytes, "AES");
    }

    public static byte[] generateIV16() {
        byte[] iv = new byte[16];
        SecureRandom rng;
        try {
            rng = SecureRandom.getInstanceStrong();
        } catch (Exception e) {
            rng = new SecureRandom();
        }
        rng.nextBytes(iv);
        return iv;
    }

    public static CipherResult aesEncrypt(byte[] plaintext, SecretKeySpec key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = generateIV16();
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] ct = cipher.doFinal(plaintext);
        return new CipherResult(ct, iv);
    }

    public static byte[] aesDecrypt(byte[] ciphertext, SecretKeySpec key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        return cipher.doFinal(ciphertext);
    }

    // -- Base64 helpers for display/storage -------------------------------
    public static String toBase64(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }

    public static byte[] fromBase64(String s) {
        return Base64.getDecoder().decode(s);
    }

    // Small container class to return ciphertext + iv
    public static class CipherResult {
        public final byte[] ciphertext;
        public final byte[] iv;

        public CipherResult(byte[] ciphertext, byte[] iv) {
            this.ciphertext = ciphertext;
            this.iv = iv;
        }
    }
}

