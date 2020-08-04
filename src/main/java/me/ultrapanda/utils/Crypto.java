package me.ultrapanda.utils;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class Crypto {
    private BASE64Encoder base64Encoder;
    private BASE64Decoder base64Decoder;
    private final int keySize = 2048;

    public Crypto() {
        this.base64Encoder = new BASE64Encoder();
        this.base64Decoder = new BASE64Decoder();
    }

    public byte[] encryptMD5(byte[] bytes) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("md5");
        return messageDigest.digest(bytes);
    }

    public String encryptBase64(byte[] bytes) {
        return base64Encoder.encode(bytes);
    }

    public byte[] decryptBase64(String string) throws IOException {
        return base64Decoder.decodeBuffer(string);
    }

    public byte[] encryptRSA(PrivateKey privateKey, byte[] bytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        return cipher.doFinal(bytes);
    }

    public byte[] decryptRSA(PublicKey publicKey, byte[] bytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        return cipher.doFinal(bytes);
    }

    public KeyPair buildRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);

        return keyPairGenerator.generateKeyPair();
    }

    public byte[] encryptSHA512(byte[] bytes) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
        messageDigest.update(bytes);

        return messageDigest.digest();
    }

    public byte[] encryptSHA256(byte[] bytes) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(bytes);

        return messageDigest.digest();
    }

    public String hexToString(byte[] bytes){
        StringBuffer hexString = new StringBuffer();

        for (int i = 0; i < bytes.length; i++) {
            if ((0xff & bytes[i]) < 0x10) {
                hexString.append("0" + Integer.toHexString((0xFF & bytes[i])));
            } else {
                hexString.append(Integer.toHexString(0xFF & bytes[i]));
            }
        }

        return hexString.toString();
    }

    public String encryptMD5ToString(String string) throws NoSuchAlgorithmException {
        return hexToString(encryptMD5(string.getBytes(StandardCharsets.UTF_8)));
    }

    public byte[] encryptAES(byte[] data, byte[] keyData) throws Exception {
        Key key = toKey(keyData);
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        return cipher.doFinal(data);
    }

    public byte[] decryptAES(byte[] data, byte[] keyData) throws Exception {
        Key key = toKey(keyData);
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);

        return cipher.doFinal(data);
    }

    public static Key toKey(byte[] key) throws Exception {
        return new SecretKeySpec(key, "AES");
    }

    public byte[] generateAESKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey secretKey = kg.generateKey();
        return secretKey.getEncoded();
    }
}
