import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Objects;

public class Cryptography {
//    private static final String SALT = "ssshhhhhhhhhhh!!!!";

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

        Steganography.EncryptionChaining chaining=Steganography.EncryptionChaining.CBC;
        Steganography.EncryptionCypher encryptionCypher= Steganography.EncryptionCypher.AES128;

        String plaintext="this is the test string akjsjhdkajhskd djhasksjfhksjhfkjsdhkfjhsdkjfhksdjhfkjsdjhfakjsjhdkajhskd djhasksjfhksjhfkjsdhkfjhsdkjfhksdjhfkjsdjhfakjsjhdkajhskd djhasksjfhksjhfkjsdhkfjhsdkjfhksdjhfkjsdjhfakjsjhdkajhskd djhasksjfhksjhfkjsdhkfjhsdkjfhksdjhfkjsdjhfakjsjhdkajhskd djhasksjfhksjhfkjsdhkfjhsdkjfhksdjhfkjsdjhfakjsjhdkajhskd djhasksjfhksjhfkjsdhkfjhsdkjfhksdjhfkjsdjhfakjsjhdkajhskd djhasksjfhksjhfkjsdhkfjhsdkjfhksdjhfkjsdjhfakjsjhdkajhskd djhasksjfhksjhfkjsdhkfjhsdkjfhksdjhfkjsdjhfakjsjhdkajhskd djhasksjfhksjhfkjsdhkfjhsdkjfhksdjhfkjsdjhfakjsjhdkajhskd djhasksjfhksjhfkjsdhkfjhsdkjfhksdjhfkjsdjhfakjsjhdkajhskd djhasksjfhksjhfkjsdhkfjhsdkjfhksdjhfkjsdjhfakjsjhdkajhskd djhasksjfhksjhfkjsdhkfjhsdkjfhksdjhfkjsdjhfakjsjhdkajhskd djhasksjfhksjhfkjsdhkfjhsdkjfhksdjhfkjsdjhfakjsjhdkajhskd djhasksjfhksjhfkjsdhkfjhsdkjfhksdjhfkjsdjhfakjsjhdkajhskd djhasksjfhksjhfkjsdhkfjhsdkjfhksdjhfkjsdjhfakjsjhdkajhskd djhasksjfhksjhfkjsdhkfjhsdkjfhksdjhfkjsdjhfkjshdkfjhsdkjfhskdkjhfksjdhfkjsdhfkjsdhdfkjkjhasdkjfjhaksjdhfkjasadhdfkjkashddkfjhaskdkjdhfhkasjdjhf";
//        System.out.println(Arrays.toString(plaintext.getBytes()));
        System.out.println(plaintext);

        byte[] cypher=encrypt(chaining, encryptionCypher,"pass",plaintext.getBytes());
        System.out.println(Arrays.toString(cypher));
//        System.out.println(Arrays.toString(decrypt(chaining, encryptionCypher,"pass",cypher)));
        System.out.println(new String(decrypt(chaining, encryptionCypher,"pass",cypher)));
    }

    private static byte[] encrypt(
    Steganography.EncryptionChaining chaining,Steganography.EncryptionCypher cypher,String password,byte[] content) throws IllegalBlockSizeException, NoSuchPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException, InvalidKeyException {
        if (cypher== Steganography.EncryptionCypher.DES){
            return encryptDES(chaining.toString(), password,content);
        }
        String bits=cypher.toString().substring(3);
        int keyLen =Integer.decode(bits);
        keyLen/=8;

        return encryptAES(chaining.toString(), password,content,keyLen);

    }
    private static byte[] decrypt(
            Steganography.EncryptionChaining chaining,Steganography.EncryptionCypher cypher,String password,byte[] content) throws IllegalBlockSizeException, NoSuchPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException, InvalidKeyException {
        if (cypher== Steganography.EncryptionCypher.DES){
            return decryptDES(chaining.toString(), password,content);
        }
        String bits=cypher.toString().substring(3);
        int keyLen =Integer.decode(bits);
        keyLen/=8;

        return decryptAES(chaining.toString(), password,content,keyLen);

    }


    private static byte[][] generateKeyAndIv(String password, int keylen, int blocksize) {
        // Implementacion de EVP_BytesToKey: https://www.openssl.org/docs/man1.1.0/crypto/EVP_BytesToKey.html

        byte[] data = password.getBytes();
        byte[][] result=new byte[2][];

        MessageDigest digestor = null;

        try {
            final String HASH_ALGORITHM = "SHA-256";
            digestor = MessageDigest.getInstance(HASH_ALGORITHM);
        } catch (NoSuchAlgorithmException ignored) {}

        int requiredLength = keylen + blocksize;

        // Me aseguro de generar suficientes bytes
        int iterations = (requiredLength / digestor.getDigestLength()) + (requiredLength % digestor.getDigestLength() == 0 ? 0 : 1);
        byte[] keyData = new byte[iterations * digestor.getDigestLength()];

        byte[] prev = {}; // D_i
        int offset = 0;   //
        for (int i = 0 ; i < iterations ; i++) {
            byte[] hashable = new byte[prev.length + data.length];
            // Concatenate D_(n-1) || data
            // (No salt)
            System.arraycopy(prev, 0, hashable, 0, prev.length);
            System.arraycopy(data, 0, hashable, prev.length, data.length);

            prev = digestor.digest(hashable); // D_n
            System.arraycopy(prev, 0, keyData, offset, prev.length);
            offset += prev.length;
        }

        result[0] = Arrays.copyOfRange(keyData,0, keylen);
        result[1] = Arrays.copyOfRange(keyData, keylen, requiredLength);

        return result;
    }


    private static byte[] encryptDES(String chaining, String password, byte[]content){
        try {

            byte[][]keys=generateKeyAndIv(password, 8, 8);
            IvParameterSpec ivspec = new IvParameterSpec(keys[1]);
            SecretKeySpec secretKey = new SecretKeySpec(keys[0], "DES");

            String padding;
            switch (chaining){
                case "ECB": padding="PKCS5Padding"; break;
                case "CFB": padding="NOPADDING"; chaining="CFB8"; break;
                case "OFB": padding="NOPADDING"; break;
                case "CBC": padding="PKCS5Padding"; break;
                default:
                    throw new RuntimeException("Chaining method not found "+ chaining);
            }
            Cipher cipher = Cipher.getInstance("DES/"+chaining+"/"+padding);
            if (Objects.equals(chaining, "ECB"))
                cipher.init(Cipher.ENCRYPT_MODE,secretKey);
            else
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
            return cipher.doFinal(content);
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;

    }
    private static byte[] decryptDES(String chaining, String password, byte[]content){
        try {
            byte[][]keys=generateKeyAndIv(password, 8, 8);
            IvParameterSpec ivspec = new IvParameterSpec(keys[1]);
            SecretKeySpec secretKey = new SecretKeySpec(keys[0], "DES");

            String padding;
            switch (chaining){
                case "ECB": padding="PKCS5Padding"; break;
                case "CFB": padding="NOPADDING"; chaining="CFB8"; break;
                case "OFB": padding="NOPADDING"; break;
                case "CBC": padding="PKCS5Padding"; break;
                default:
                    throw new RuntimeException("Chaining method not found "+ chaining);
            }

            Cipher cipher = Cipher.getInstance("DES/"+chaining+"/"+padding);
            if (Objects.equals(chaining,"ECB"))
                cipher.init(Cipher.DECRYPT_MODE, secretKey);
            else
                cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
            return cipher.doFinal(content);
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;

    }


    private static byte[] encryptAES(String chaining, String password, byte[] content, int keyLen) {
        try {
//            byte[][]keys=EVP_BytesToKey(keyLen,ivLen,MessageDigest.getInstance("SHA256"),null,password.getBytes(),65536);
            byte[][]keys=generateKeyAndIv(password,keyLen, 16);
            IvParameterSpec ivspec = new IvParameterSpec(keys[1]);
            SecretKeySpec secretKey = new SecretKeySpec(keys[0], "AES");
            String padding;
            switch (chaining){
                case "ECB": padding="PKCS5Padding"; break;
                case "CFB": padding="NOPADDING"; chaining="CFB8"; break;
                case "OFB": padding="NOPADDING"; break;
                case "CBC": padding="PKCS5Padding"; break;
                default:
                    throw new RuntimeException("Chaining method not found "+ chaining);
            }

            Cipher cipher = Cipher.getInstance("AES/"+chaining+"/"+padding);
            if (chaining.equals("ECB"))
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            else
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
            return cipher.doFinal(content);
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }
    private static byte[] decryptAES(String chaining, String password, byte[] content, int keyLen) {
        try {
            //byte[][]keys=EVP_BytesToKey(keyLen,ivLen,MessageDigest.getInstance("SHA256"),null,password.getBytes(),65536);
            byte[][]keys=generateKeyAndIv(password,keyLen, 16); IvParameterSpec ivspec = new IvParameterSpec(keys[1]);
            SecretKeySpec secretKey = new SecretKeySpec(keys[0], "AES");
            String padding;
            switch (chaining){
                case "ECB": padding="PKCS5Padding"; break;
                case "CFB": padding="NOPADDING"; chaining="CFB8"; break;
                case "OFB": padding="NOPADDING"; break;
                case "CBC": padding="PKCS5Padding"; break;
                default:
                    throw new RuntimeException("Chaining method not found "+ chaining);
            }

            Cipher cipher = Cipher.getInstance("AES/"+chaining+"/"+padding);
            if (chaining.equals("ECB"))
                cipher.init(Cipher.DECRYPT_MODE, secretKey);
            else
                cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
            return cipher.doFinal(content);
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }
}
