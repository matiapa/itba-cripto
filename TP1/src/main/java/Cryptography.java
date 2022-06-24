
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.charset.StandardCharsets;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

public class Cryptography {
    private static final String SALT = "ssshhhhhhhhhhh!!!!";

    public static byte[] encrypt(byte[] data, String password, Steganography.EncryptionCypher cypher, Steganography.EncryptionChaining chaining) throws IllegalBlockSizeException, NoSuchPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException, InvalidKeyException {
        return encrypt(chaining,cypher,password,data);
    }

    public static byte[] decrypt(byte[] data, String password, Steganography.EncryptionCypher cypher, Steganography.EncryptionChaining chaining) throws IllegalBlockSizeException, NoSuchPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException, InvalidKeyException {
        return decrypt(chaining,cypher,password,data);
    }


    public static void main(String[] args) throws Exception {

//        Security.setProperty("crypto.policy", "unlimited");
//        int maxKeySize = javax.crypto.Cipher.getMaxAllowedKeyLength("AES");
//        System.out.println("Max Key Size for AES : " + maxKeySize);
//        Security.addProvider(new BouncyCastleProvider());

        Steganography.EncryptionChaining chaining = Steganography.EncryptionChaining.CBC;
        Steganography.EncryptionCypher encryptionCypher = Steganography.EncryptionCypher.AES128;

        System.out.println(Arrays.toString("this is the test string".getBytes()));

        byte[] cypher = encrypt(chaining, encryptionCypher,"pass", "this is the test string".getBytes());
        System.out.println(Arrays.toString(cypher));
        System.out.println(Arrays.toString(decrypt(chaining, encryptionCypher,"pass", cypher)));

    }

    private static byte[] encrypt(
    Steganography.EncryptionChaining chaining,Steganography.EncryptionCypher cypher,String password,byte[] content) throws IllegalBlockSizeException, NoSuchPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException, InvalidKeyException {
        if (cypher== Steganography.EncryptionCypher.DES){
            return encryptDES(chaining.toString(),password,content);
        }
        String bits=cypher.toString().substring(3);
        int keyLen =Integer.decode(bits);
        keyLen/=8;

        return encryptAES(chaining.toString(),password,content,keyLen);

    }
    private static byte[] decrypt(
            Steganography.EncryptionChaining chaining,Steganography.EncryptionCypher cypher,String password,byte[] content) throws IllegalBlockSizeException, NoSuchPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException, InvalidKeyException {
        if (cypher== Steganography.EncryptionCypher.DES){
            return decryptDES(chaining.toString(),password,content);
        }
        String bits=cypher.toString().substring(3);
        int keyLen =Integer.decode(bits);
        keyLen/=8;

        return decryptAES(chaining.toString(),password,content,keyLen);

    }

    public static byte[][] EVP_BytesToKey(int key_len, int iv_len, MessageDigest md, byte[] salt, byte[] data, int count) {
        byte[][] both = new byte[2][];
        byte[] key = new byte[key_len];
        int key_ix = 0;
        byte[] iv = new byte[iv_len];
        int iv_ix = 0;
        both[0] = key;
        both[1] = iv;
        byte[] md_buf = null;
        int nkey = key_len;
        int niv = iv_len;
        int i = 0;
        if (data == null) {
            return both;
        }
        int addmd = 0;
        for (; ; ) {
            md.reset();
            if (addmd++ > 0) {
                md.update(md_buf);
            }
            md.update(data);
            if (null != salt) {
                md.update(salt, 0, 8);
            }
            md_buf = md.digest();
            for (i = 1; i < count; i++) {
                md.reset();
                md.update(md_buf);
                md_buf = md.digest();
            }
            i = 0;
            if (nkey > 0) {
                for (; ; ) {
                    if (nkey == 0)
                        break;
                    if (i == md_buf.length)
                        break;
                    key[key_ix++] = md_buf[i];
                    nkey--;
                    i++;
                }
            }
            if (niv > 0 && i != md_buf.length) {
                for (; ; ) {
                    if (niv == 0)
                        break;
                    if (i == md_buf.length)
                        break;
                    iv[iv_ix++] = md_buf[i];
                    niv--;
                    i++;
                }
            }
            if (nkey == 0 && niv == 0) {
                break;
            }
        }
        for (i = 0; i < md_buf.length; i++) {
            md_buf[i] = 0;
        }
        return both;
    }
    private static byte[] encryptDES(String chaining,String password,byte[] content) throws IllegalBlockSizeException, NoSuchPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException, InvalidKeyException {
        switch (chaining.toUpperCase()){
            case "ECB":
                return encryptDESECB(password,content);
            case "CFB":
                return encryptDESOther("CFB8",16,password,content);
            case "OFB":
                return encryptDESOther("OFB",16,password,content);
            case "CBC":
                return encryptDESOther("CBC",16,password,content);
            default:
                throw new UnsupportedEncodingException();
        }
    }

    private static byte[] decryptDES(String chaining,String password,byte[] content) throws IllegalBlockSizeException, NoSuchPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException, InvalidKeyException {
        switch (chaining.toUpperCase()){
            case "ECB":
                return decryptDESECB(password,content);
            case "CFB":
                return decryptDESOther("CFB8",16,password,content);
            case "OFB":
                return decryptDESOther("OFB",16,password,content);
            case "CBC":
                return decryptDESOther("CBC",16,password,content);
            default:
                throw new UnsupportedEncodingException();
        }
    }
    private static byte[] encryptDESECB(String password,byte[] content) throws NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidKeySpecException {
        //Se genera la clave para DES
        SecretKeySpec secretKey = new SecretKeySpec(password.getBytes(), "DES");

        //Se genera instancia de Cipher

        Cipher desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
//        Cipher desCipher = Cipher.getInstance("AES/CFB8/NoPadding");
        //Se inicializa el cifrador para poder encriptar con la clave
        desCipher.init(Cipher.ENCRYPT_MODE, secretKey);
        //Se encripta
        return desCipher.doFinal(content);
    }

    private static byte[] decryptDESECB(String password,byte[] content) throws NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidKeySpecException {
        //Se genera la clave para DES
        SecretKeySpec secretKey = new SecretKeySpec(password.getBytes(), "DES");

        //Se genera instancia de Cipher

        Cipher desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        //Se inicializa el cifrador para poder encriptar con la clave
        desCipher.init(Cipher.DECRYPT_MODE, secretKey);
        return desCipher.doFinal(content);
    }

    private static byte[] encryptDESOther(String chaining,int ivLen,String password,byte[]content){
        try {

            byte[][]keys=EVP_BytesToKey(8,ivLen,MessageDigest.getInstance("SHA256"),null,password.getBytes(),65536);
            IvParameterSpec ivspec = new IvParameterSpec(keys[1]);
            SecretKeySpec secretKey = new SecretKeySpec(keys[0], "DES");
            Cipher cipher = Cipher.getInstance("DES/"+chaining+"/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
            return cipher.doFinal(content);
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;

    }
    private static byte[] decryptDESOther(String chaining,int ivLen,String password,byte[]content){
        try {
            byte[][]keys=EVP_BytesToKey(8,ivLen,MessageDigest.getInstance("SHA256"),null,password.getBytes(),65536);
            IvParameterSpec ivspec = new IvParameterSpec(keys[1]);
            SecretKeySpec secretKey = new SecretKeySpec(keys[0], "DES");
            Cipher cipher = Cipher.getInstance("DES/"+chaining+"/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
            return cipher.doFinal(content);
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;

    }



    private static byte[] encryptAES(String chaining,String password,byte[] content,int keyLength) throws IllegalBlockSizeException, NoSuchPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException, InvalidKeyException {
        switch (chaining.toUpperCase()){
            case "ECB":
                return encryptAESECB(password,content,keyLength);
            case "CFB":
                return encryptAESOther("CFB8",16,password,content,keyLength);
            case "OFB":
                return encryptAESOther("OFB",16,password,content,keyLength);
            case "CBC":
                return encryptAESOther("CBC",16,password,content,keyLength);
            default:
                throw new UnsupportedEncodingException();
        }
    }

    private static byte[] decryptAES(String chaining,String password,byte[] content,int keyLength) throws IllegalBlockSizeException, NoSuchPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException, InvalidKeyException {
        switch (chaining.toUpperCase()){
            case "ECB":
                return decryptAESECB(password,content,keyLength);
            case "CFB":
                return decryptAESOther("CFB8",16,password,content,keyLength);
            case "OFB":
                return decryptAESOther("OFB",16,password,content,keyLength);
            case "CBC":
                return decryptAESOther("CBC",16,password,content,keyLength);
            default:
                throw new UnsupportedEncodingException();
        }
    }

    private static byte[] encryptAESECB(String password,byte[] content,int keyLen) {
        try {
            byte[][]keys=EVP_BytesToKey(keyLen,0,MessageDigest.getInstance("SHA256"),null,password.getBytes(),65536);
            IvParameterSpec ivspec = new IvParameterSpec(keys[1]);
            SecretKeySpec secretKey = new SecretKeySpec(keys[0], "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return cipher.doFinal(content);
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }
    private static byte[] decryptAESECB(String password,byte[] content,int keyLen) {
        try {
            byte[][]keys=EVP_BytesToKey(keyLen,0,MessageDigest.getInstance("SHA256"),null,password.getBytes(),65536);
            IvParameterSpec ivspec = new IvParameterSpec(keys[1]);
            SecretKeySpec secretKey = new SecretKeySpec(keys[0], "AES");

            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return cipher.doFinal(content);
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }
    private static byte[] encryptAESOther(String chaining,int ivLen,String password,byte[] content,int keyLen) {
        try {
            byte[][]keys=EVP_BytesToKey(keyLen,ivLen,MessageDigest.getInstance("SHA256"),null,password.getBytes(),65536);
            IvParameterSpec ivspec = new IvParameterSpec(keys[1]);
            SecretKeySpec secretKey = new SecretKeySpec(keys[0], "AES");
            Cipher cipher = Cipher.getInstance("AES/"+chaining+"/PKCS5PADDING",new BouncyCastleProvider());
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
            return cipher.doFinal(content);
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }
    private static byte[] decryptAESOther(String chaining,int ivLen,String password,byte[] content,int keyLen) {
        try {
            byte[][]keys=EVP_BytesToKey(keyLen,ivLen,MessageDigest.getInstance("SHA256"),null,password.getBytes(),65536);
            IvParameterSpec ivspec = new IvParameterSpec(keys[1]);
            SecretKeySpec secretKey = new SecretKeySpec(keys[0], "AES");

            Cipher cipher = Cipher.getInstance("AES/"+chaining+"/PKCS5Padding",new BouncyCastleProvider());
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
            return cipher.doFinal(content);
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }
}
