
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
import java.util.Base64;

public class Cryptography {
    private static final String SALT = "ssshhhhhhhhhhh!!!!";


    public static void main(String[] args) throws Exception {
//        encryptDES("blah","password","test".getBytes());
//        System.out.println(Arrays.toString("this is the test string".getBytes()));
//        byte[] cypher=encryptDES("CBC","pass","this is the test string".getBytes());
//        System.out.println(Arrays.toString(cypher));
//        System.out.println(Arrays.toString(decryptDES("CBC","pass", cypher)));

    }
    
    private static class KeyInternal{
        final private byte[] iv;
        final private byte[] key;

        public KeyInternal(byte[] iv, byte[] key) {
            this.iv = iv;
            this.key = key;
        }

        public byte[] getIv() {
            return iv;
        }

        public byte[] getKey() {
            return key;
        }
    }

    private static KeyInternal generateKey(byte[] pass, int count,int keyLength) throws NoSuchAlgorithmException {

        byte[] data=new byte[256];
        System.arraycopy(pass,0,data,0,pass.length);
        MessageDigest mdSha256 = MessageDigest.getInstance("SHA-256");
        for (int i = 0; i < count; i++) {
            mdSha256.update(data);
            data=mdSha256.digest();
        }

        byte[]key=new byte[keyLength/8];
        byte[]iv=new byte[16];

        System.arraycopy(data,0,key,0,keyLength/8);
        System.arraycopy(data,0,iv,0,16);
        return new KeyInternal(iv,key);
    }


    public static byte[] encryptDES(String chaining,String password,byte[] content) throws IllegalBlockSizeException, NoSuchPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException, InvalidKeyException {
        switch (chaining.toUpperCase()){
            case "ECB":
                return encryptDESECB(password,content);
            case "CFB":
            case "OFB":
            case "CBC":
                return encryptDESOther(chaining.toUpperCase(),password,content);
            default:
                throw new UnsupportedEncodingException();
        }
    }

    public static byte[] decryptDES(String chaining,String password,byte[] content) throws IllegalBlockSizeException, NoSuchPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException, InvalidKeyException {
        switch (chaining.toUpperCase()){
            case "ECB":
                return decryptDESECB(password,content);
            case "CFB":
            case "OFB":
            case "CBC":
                return decryptDESOther(chaining.toUpperCase(),password,content);
            default:
                throw new UnsupportedEncodingException();
        }
    }
    public static byte[] encryptDESECB(String password,byte[] content) throws NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidKeySpecException {
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

    public static byte[] decryptDESECB(String password,byte[] content) throws NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidKeySpecException {
        //Se genera la clave para DES
        SecretKeySpec secretKey = new SecretKeySpec(password.getBytes(), "DES");

        //Se genera instancia de Cipher

        Cipher desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        //Se inicializa el cifrador para poder encriptar con la clave
        desCipher.init(Cipher.DECRYPT_MODE, secretKey);
        return desCipher.doFinal(content);
    }

    public static byte[] encryptDESOther(String chaining,String password,byte[]content){
        try {
            KeyInternal key=generateKey(password.getBytes(),65536,56);
            IvParameterSpec ivspec = new IvParameterSpec(key.getIv());
            SecretKeySpec secretKey = new SecretKeySpec(key.getKey(), "DES");
            Cipher cipher = Cipher.getInstance("DES/"+chaining+"/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
            return cipher.doFinal(content);
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;

    }
    public static byte[] decryptDESOther(String chaining,String password,byte[]content){
        try {
            KeyInternal key=generateKey(password.getBytes(),65536,56);
            IvParameterSpec ivspec = new IvParameterSpec(key.getIv());
            SecretKeySpec secretKey = new SecretKeySpec(key.getKey(), "DES");
            Cipher cipher = Cipher.getInstance("DES/"+chaining+"/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
            return cipher.doFinal(content);
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;

    }



    public static byte[] encryptAES(String chaining,String password,byte[] content,int keyLength) throws IllegalBlockSizeException, NoSuchPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException, InvalidKeyException {
        switch (chaining.toUpperCase()){
            case "ECB":
                return encryptAESECB(password,content,keyLength);
            case "CFB":
            case "OFB":
            case "CBC":
                return encryptAESOther(chaining.toUpperCase(),password,content,keyLength);
            default:
                throw new UnsupportedEncodingException();
        }
    }

    public static byte[] decryptAES(String chaining,String password,byte[] content,int keyLength) throws IllegalBlockSizeException, NoSuchPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException, InvalidKeyException {
        switch (chaining.toUpperCase()){
            case "ECB":
                return decryptDESECB(password,content);
            case "CFB":
            case "OFB":
            case "CBC":
                return decryptAESOther(chaining.toUpperCase(),password,content,keyLength);
            default:
                throw new UnsupportedEncodingException();
        }
    }

    public static byte[] encryptAESECB(String password,byte[] content,int keyLen) {
        try {
            KeyInternal key=generateKey(password.getBytes(),65536,keyLen);
            SecretKeySpec secretKey = new SecretKeySpec(key.getKey(), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return cipher.doFinal(content);
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }
    public static byte[] decryptAESECB(String password,byte[] content,int keyLen) {
        try {
            KeyInternal key=generateKey(password.getBytes(),65536,keyLen);
            SecretKeySpec secretKey = new SecretKeySpec(key.getKey(), "AES");

            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return cipher.doFinal(content);
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }
    public static byte[] encryptAESOther(String chaining,String password,byte[] content,int keyLen) {
        try {
            KeyInternal key=generateKey(password.getBytes(),65536,keyLen);
            IvParameterSpec ivspec = new IvParameterSpec(key.getIv());
            SecretKeySpec secretKey = new SecretKeySpec(key.getKey(), "AES");
            Cipher cipher = Cipher.getInstance("AES/"+chaining+"/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
            return cipher.doFinal(content);
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }
    public static byte[] decryptAESOther(String chaining,String password,byte[] content,int keyLen) {
        try {
            KeyInternal key=generateKey(password.getBytes(),65536,keyLen);
            IvParameterSpec ivspec = new IvParameterSpec(key.getIv());
            SecretKeySpec secretKey = new SecretKeySpec(key.getKey(), "AES");

            Cipher cipher = Cipher.getInstance("AES/"+chaining+"/PKCS5Padding\"");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
            return cipher.doFinal(content);
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }
}
