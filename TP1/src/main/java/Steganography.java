import java.io.*;
import java.nio.ByteBuffer;

public class Steganography {

    public static void encode(File hostFile, File payloadFile) throws IOException {
        if(!hostFile.getName().split("\\.")[1].equals("bmp"))
            throw new RuntimeException("Host file must be a BMP");

        // Read host file

        FileInputStream is = new FileInputStream(hostFile);
        byte[] targetBytes = new byte[(int) hostFile.length()];
        is.read(targetBytes);

        // Write payload size

        int payloadSize = (int) payloadFile.length();
        byte[] srcBytes = ByteBuffer.allocate(4).putInt(payloadSize).array();

        int t = lsb1(srcBytes, targetBytes, 0);

        // Write payload data

        is = new FileInputStream(payloadFile);
        srcBytes = new byte[(int) payloadFile.length()];
        is.read(srcBytes);

        t = lsb1(srcBytes, targetBytes, t);

        // Write extension name

        String extensionName = payloadFile.getName().split("\\.")[1];
        srcBytes = extensionName.getBytes();

        lsb1(srcBytes, targetBytes, t);

        // Write target bytes to host file

        FileOutputStream os = new FileOutputStream("out.bmp");
        os.write(targetBytes);
    }

    static int lsb1(byte[] srcBytes, byte[] targetBytes, int targetOffsetBits) {
        int srcBitN=0, targetBitN=7+targetOffsetBits;
        while(srcBitN < srcBytes.length * 8) {
            copyBit(srcBytes, srcBitN, targetBytes, targetBitN);
            srcBitN++; targetBitN+=8;
        }
        return targetBitN;
    }

    static void copyBit(byte[] src, int srcBitN, byte[] target, int targetBitN) {
        int mask = 1 << (7 - srcBitN % 8);
        int bit = (src[srcBitN / 8] & mask) >> (7 - srcBitN % 8);

        if(bit == 1)
            target[targetBitN / 8] |= 1 << (7 - targetBitN % 8);
        else
            target[targetBitN / 8] &= ~(1 << (7 - targetBitN % 8));
    }

    public static void main(String[] args) throws IOException {
        File hostFile = new File("host.bmp");
        File payloadFile = new File("payload.bin");

        encode(hostFile, payloadFile);
    }

}
